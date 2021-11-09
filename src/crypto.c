#include "crypto.h"
#include <stdio.h>
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

BCRYPT_ALG_HANDLE initialize_aes_algorithm()
{
    NTSTATUS err;
    BCRYPT_ALG_HANDLE hAesAlg;

    if(!NT_SUCCESS(err = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptOpenAlgorithmProvider\n", err);
        return NULL;
    }
    //printf("[+] Created AES algorithm handle\n");
    return hAesAlg;
}
AES_KEY *get_aes_key_struct(PBYTE key, DWORD key_size)
{
    AES_KEY *a = (AES_KEY *) HeapAlloc(GetProcessHeap(), 0, sizeof(AES_KEY));
    if(a == NULL) return NULL;

    a->key_size = key_size;
    a->iv_size = 0;

    a->iv = NULL;
    a->key = NULL;

    if(key != NULL && a->key_size > 0)
    {
        a->key = HeapAlloc(GetProcessHeap(), 0, a->key_size);
        memcpy(a->key, key, a->key_size);
    }

    a->key_object = NULL;
    a->key_object_size = 0;
    a->hKey = NULL;
    a->block_length = CRYPTO_IV_SIZE;

    return a;
}
void free_aes_key_struct(AES_KEY *a)
{
    if(a == NULL) return;

    if(a->key) HeapFree(GetProcessHeap(), 0, a->key);
    if(a->iv) HeapFree(GetProcessHeap(), 0, a->iv);

    if(a->hKey) BCryptDestroyKey(a->hKey);
    if(a->key_object) HeapFree(GetProcessHeap(), 0, a->key_object);
    HeapFree(GetProcessHeap(), 0, a);
}
// IV is expected to be 16 Bytes long
void create_symmetric_key_object(BCRYPT_ALG_HANDLE hAesAlg, AES_KEY *a)
{
    if(hAesAlg == NULL) return;

    NTSTATUS err;

    DWORD cbData;

    // Buffer size for key object
    if(!NT_SUCCESS(err = BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PVOID) &a->key_object_size, sizeof(a->key_object_size), &cbData, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptGetProperty\n", err);
        return;
    }
    //printf("[+] Got key object size: %lu\n", a->key_object_size);

    // Allocate memory for key object
    a->key_object = (PBYTE) HeapAlloc(GetProcessHeap(), 0, a->key_object_size);
    if(a->key_object == NULL)
    {
        printf("**** memory allocation failed\n");
        return;
    }
    //printf("[+] Allocated memory for key object\n");

    // Buffer size for IV
    if(!NT_SUCCESS(err = BCryptGetProperty(hAesAlg, BCRYPT_BLOCK_LENGTH, (PBYTE) &a->block_length, sizeof(DWORD), &cbData, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptGetProperty\n", err);
        return;
    }

    // If IV is not given create a random one
    if(a->iv == NULL)
    {
        a->iv = get_random_bytes(a->block_length);
        a->iv_size = a->block_length;
        if(a->iv == NULL)
        {
            printf("Could not get random bytes for IV\n");
            return;
        }
        //printf("[+] Created random IV\n");
    }

    // Set property of aes
    if(!NT_SUCCESS(err = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE) BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
    {
        printf("**** Error 0x%lx returned by BCryptSetProperty\n", err);
        return;
    }

    // Generate the key if not given
    if(a->key == NULL)
    {
        a->key_size = 32;
        a->key = get_random_bytes(a->key_size);
        if(a->key == NULL)
        {
            printf("Could not get random bytes for Key\n");
            return;
        }
        printf("[+] Created random Key\n");
    }

    if(!NT_SUCCESS(err = BCryptGenerateSymmetricKey(hAesAlg, &a->hKey, a->key_object, a->key_object_size, a->key, a->key_size, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptGenerateSymmetricKey\n", err);
        return;
    }
    //printf("[+] Created symmetric key\n");
}
LONGLONG aes_encrypt(AES_KEY *a, FILE *fp, LONGLONG f_size)
{
    if(a == NULL || fp == NULL || f_size == 0) return 0;

    NTSTATUS err;
    LONGLONG cipher_size;
    DWORD bytes_encrypted;
    LONGLONG total_bytes_encrypted = 0;
    size_t bytes_read;
    BYTE buffer[CRYPTO_BUFFER_SIZE];

    // Get the size of the cipher text
    if(!NT_SUCCESS(err = BCryptEncrypt(a->hKey, NULL, f_size, NULL, a->iv, a->iv_size, NULL, 0, (ULONG *) &cipher_size, BCRYPT_BLOCK_PADDING)))
    {
        printf("**** Error 0x%lx returned by BCryptEncrypt\n", err);
        return 0;
    }

    // Copy IV in separate buffer to spare the original
    PBYTE iv_copy = HeapAlloc(GetProcessHeap(), 0, a->iv_size);
    if(iv_copy == NULL)
    {
        printf("Could not allocate space for iv\n");
        return 0;
    }

    memcpy(iv_copy, a->iv, a->iv_size);

    // Read the first 16 bytes to link them with the iv and aes encrypt
    // if file size is smaller than 16 fread will only read as much as possible
    bytes_read = fread(buffer, 1, sizeof(buffer), fp);

    // Encrypt the first block and check if it is smaller than 16 byte
    if(!NT_SUCCESS(err = BCryptEncrypt(a->hKey, buffer, (bytes_read < 16) ? bytes_read : 16, NULL, iv_copy,
                                       a->block_length, buffer, sizeof(buffer), &bytes_encrypted,
                                       (bytes_read < 16) ? BCRYPT_BLOCK_PADDING : 0)))
    {
        printf("**** Error 0x%lx returned by BCryptEncrypt only iv\n", err);
        return 0;
    }


    // revert the file pointer to the beginning
    rewind(fp);

    // Write the data to the file -> by writing the file pointer will be at +16 again
    fwrite(buffer, 1, bytes_encrypted, fp);
    fflush(fp);

    total_bytes_encrypted += bytes_encrypted;

    // Check if there is only block to encrypt
    if(cipher_size > 16)
    {
        while(total_bytes_encrypted < cipher_size)
        {
            // Encrypt 16 Bytes at the time
            bytes_read = fread(buffer, 1, sizeof(buffer), fp);

            if(!NT_SUCCESS(
                    err = BCryptEncrypt(a->hKey, buffer, bytes_read, NULL, NULL, 0, buffer, sizeof(buffer),
                                        &bytes_encrypted, (bytes_read < 16) ? BCRYPT_BLOCK_PADDING : 0)))
            {
                printf("**** Error 0x%lx returned by BCryptEncrypt\n", err);
                return 0;
            }
            fseek(fp, - (long) bytes_read, SEEK_CUR);
            fwrite(buffer, 1, bytes_encrypted, fp);
            fflush(fp);
            total_bytes_encrypted += bytes_encrypted;
        }
    }

    HeapFree(GetProcessHeap(), 0, iv_copy);

    // Place the iv at the end of the file
    fwrite(a->iv, 1, a->iv_size, fp);
    fflush(fp);
    return total_bytes_encrypted;
}
// f_size is expected to be calculated without the iv
LONGLONG aes_decrypt(AES_KEY *a, FILE *fp, LONGLONG f_size)
{
    if(a == NULL || fp == NULL || f_size < 16) return 0;

    NTSTATUS err;
    DWORD bytes_decrypted;
    LONGLONG total_bytes_decrypted = 0;
    size_t bytes_read;
    BYTE buffer[CRYPTO_BUFFER_SIZE];

    // Read the first 16 bytes to link them with the iv and aes decrypt
    bytes_read = fread(buffer, 1, sizeof(buffer), fp);

    // Decrypt first block with iv
    if(!NT_SUCCESS(err = BCryptDecrypt(a->hKey, buffer, bytes_read, NULL, a->iv, a->iv_size, buffer, sizeof(buffer),
                                       &bytes_decrypted, (f_size == a->block_length) ? BCRYPT_BLOCK_PADDING : 0)))
    {
        printf("**** Error 0x%lx returned by BCryptDecrypt only iv\n", err);
        return 0;
    }

    // revert the file pointer to the beginning
    rewind(fp);

    // write the decrypted data to the file
    fwrite(buffer, 1, bytes_decrypted, fp);
    fflush(fp);

    total_bytes_decrypted += bytes_decrypted;

    if(f_size > a->block_length)
    {
        while(bytes_decrypted == 16)
        {
            bytes_read = fread(buffer, 1, sizeof(buffer), fp);
            if(!NT_SUCCESS(
                    err = BCryptDecrypt(a->hKey, buffer, bytes_read, NULL, NULL, 0, buffer, sizeof(buffer),
                                               &bytes_decrypted, (total_bytes_decrypted == f_size - 16) ? BCRYPT_BLOCK_PADDING : 0)))
            {
                printf("**** Error 0x%lx returned by BCryptDecrypt\n", err);
                return 0;
            }
            fseek(fp, - (long) bytes_read, SEEK_CUR);
            fwrite(buffer, 1, bytes_decrypted, fp);
            fflush(fp);
            total_bytes_decrypted += bytes_decrypted;
        }
    }
    return total_bytes_decrypted;
}

BOOL aes_encrypt_output_file(AES_KEY *a, FILE *in, LONGLONG in_size, FILE *out)
{
    if(a == NULL || in == NULL || out == NULL || in_size == 0) return 0;

    NTSTATUS err;
    LONGLONG cipher_size;
    DWORD bytes_encrypted;
    LONGLONG total_bytes_encrypted = 0;
    size_t bytes_read;
    BYTE buffer[CRYPTO_OUTPUT_BUFFER_SIZE];

    // Get the size of the cipher text -> to prevent overflow the BCryptEncrypt function is not used because it only supports size up to 4 byte
    cipher_size = in_size + (16 - (in_size % 16));

    // Copy IV in separate buffer to spare the original
    PBYTE iv_copy = HeapAlloc(GetProcessHeap(), 0, a->iv_size);
    if(iv_copy == NULL)
    {
        printf("Could not allocate space for iv\n");
        return 0;
    }

    memcpy(iv_copy, a->iv, a->iv_size);

    bytes_read = fread(buffer, 1, 16, in);

    // Encrypt the first block and check if it is smaller than 16 byte
    if(!NT_SUCCESS(err = BCryptEncrypt(a->hKey, buffer, (bytes_read < 16) ? bytes_read : 16, NULL, iv_copy,
                                       a->block_length, buffer, 16, &bytes_encrypted,
                                       (bytes_read < 16) ? BCRYPT_BLOCK_PADDING : 0)))
    {
        printf("**** Error 0x%lx returned by BCryptEncrypt only iv\n", err);
        return 0;
    }

    // Write the data to the file -> by writing the file pointer will be at +16 again
    fwrite(buffer, 1, bytes_encrypted, out);

    total_bytes_encrypted += bytes_encrypted;

    // Check if there is only block to encrypt
    if(cipher_size > 16)
    {
        while(total_bytes_encrypted < cipher_size)
        {
            // if sum of remaining bytes is bigger than buffer size -> read full buffer size
            if(in_size - total_bytes_encrypted > sizeof(buffer))
            {
                bytes_read = fread(buffer, 1, sizeof(buffer), in);
            }
            // else only read the remaining bytes and make sure to pad them later
            else
            {
                bytes_read = fread(buffer, 1, in_size - total_bytes_encrypted, in);
            }

            if(!NT_SUCCESS(
                    err = BCryptEncrypt(a->hKey, buffer, bytes_read, NULL, NULL, 0, buffer, sizeof(buffer),
                                        &bytes_encrypted, (bytes_read < sizeof(buffer)) ? BCRYPT_BLOCK_PADDING : 0)))
            {
                printf("**** Error 0x%lx returned by BCryptEncrypt\n", err);
                return 0;
            }
            fwrite(buffer, 1, bytes_encrypted, out);
            total_bytes_encrypted += bytes_encrypted;
        }
    }

    HeapFree(GetProcessHeap(), 0, iv_copy);

    // Place the iv at the end of the file
    fwrite(a->iv, 1, a->iv_size, out);
    return 1;
}

BOOL aes_decrypt_output_file(AES_KEY *a, FILE *in, LONGLONG in_size, FILE *out)
{
    if(a == NULL || in == NULL || out == NULL || in_size == 0) return 0;

    NTSTATUS err;
    DWORD bytes_decrypted;
    LONGLONG total_bytes_decrypted = 0;
    size_t bytes_read;
    BYTE buffer[CRYPTO_OUTPUT_BUFFER_SIZE];

    // Read the first 16 bytes to link them with the iv and aes decrypt
    bytes_read = fread(buffer, 1, 16, in);

    // Encrypt the first block and check if it is smaller than 16 byte
    if(!NT_SUCCESS(err = BCryptDecrypt(a->hKey, buffer, bytes_read, NULL, a->iv, a->iv_size, buffer, 16,
                                       &bytes_decrypted, (in_size == a->block_length) ? BCRYPT_BLOCK_PADDING : 0)))
    {
        printf("**** Error 0x%lx returned by BCryptDecrypt only iv\n", err);
        return 0;
    }

    // Write the data to the file -> by writing the file pointer will be at +16 again
    fwrite(buffer, 1, bytes_decrypted, out);

    total_bytes_decrypted += bytes_decrypted;

    // Check if there is only block to encrypt
    if(in_size > a->block_length)
    {
        do
        {
            // if sum of remaining bytes is bigger than buffer size -> read full buffer size
            if(in_size - total_bytes_decrypted > sizeof(buffer))
            {
                bytes_read = fread(buffer, 1, sizeof(buffer), in);
            }
            // else only read the remaining bytes and make sure to pad them later
            else
            {
                bytes_read = fread(buffer, 1, in_size - total_bytes_decrypted, in);
            }

            if(!NT_SUCCESS(
                    err = BCryptDecrypt(a->hKey, buffer, bytes_read, NULL, NULL, 0, buffer, sizeof(buffer),
                                        &bytes_decrypted, (bytes_read < sizeof(buffer)) ? BCRYPT_BLOCK_PADDING : 0)))
            {
                printf("**** Error 0x%lx returned by BCryptDecrypt\n", err);
                return 0;
            }
            fwrite(buffer, 1, bytes_decrypted, out);
            total_bytes_decrypted += bytes_decrypted;
        }while(bytes_read == sizeof(buffer));
    }
    return 1;
}

PBYTE get_random_bytes(DWORD count)
{
    if(count == 0) return NULL;

    BCRYPT_ALG_HANDLE h;
    PBYTE buffer;

    BCryptOpenAlgorithmProvider(&h, BCRYPT_RNG_ALGORITHM, NULL, 0);

    buffer = (PBYTE) HeapAlloc(GetProcessHeap(), 0, count);
    if(buffer == NULL)
    {
        fprintf(stderr, "Could not allocate memory\n");
        return NULL;
    }

    BCryptGenRandom(h, buffer, count, 0);
    BCryptCloseAlgorithmProvider(h, 0);
    return buffer;
}
BCRYPT_ALG_HANDLE initialize_sha256_algorithm()
{
    NTSTATUS err;
    BCRYPT_ALG_HANDLE hAesAlg;

    if(!NT_SUCCESS(err = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptOpenAlgorithmProvider\n", err);
        return NULL;
    }
    return hAesAlg;
}
BOOL sha256_sum(BCRYPT_ALG_HANDLE hAlg, PUCHAR plain, DWORD plain_size, PBYTE *cipher, DWORD *cipher_size)
{
    NTSTATUS err;

    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbData;

    DWORD hash_object_length;
    PBYTE hash_object = NULL;

    DWORD hash_size;
    PBYTE hash = NULL;

    // Calculate hash object size
    if(!NT_SUCCESS(err = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE) &hash_object_length, sizeof(hash_object_length), &cbData, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptGetProperty\n", err);
        goto Cleanup;
    }

    // Allocate hash object
    hash_object = HeapAlloc(GetProcessHeap(), 0, hash_object_length);
    if(hash_object == NULL)
    {
        printf("**** memory allocation failed\n");
        goto Cleanup;
    }

    //Calculate hash size
    if(!NT_SUCCESS(err = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE) &hash_size, sizeof(hash_size), &cbData, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptGetProperty\n", err);
        goto Cleanup;
    }

    hash = HeapAlloc(GetProcessHeap(), 0, hash_size);
    if(hash == NULL)
    {
        printf("**** memory allocation failed\n");
        goto Cleanup;
    }

    // Create the hash object
    if(!NT_SUCCESS(err = BCryptCreateHash(hAlg, &hHash, hash_object, hash_object_length, NULL, 0, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptCreateHash\n", err);
        goto Cleanup;
    }

    // Hash data
    if(!NT_SUCCESS(err = BCryptHashData(hHash, plain, plain_size, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptHashData\n", err);
        goto Cleanup;
    }

    // Finalize the hash
    if(!NT_SUCCESS(err = BCryptFinishHash(hHash, hash, hash_size, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptFinishHash\n", err);
        goto Cleanup;
    }

    *cipher = hash;
    *cipher_size = hash_size;

    Cleanup:

    if (hHash)
    {
        BCryptDestroyHash(hHash);
    }

    if(hash_object)
    {
        HeapFree(GetProcessHeap(), 0, hash_object);
    }

    return 1;
}
