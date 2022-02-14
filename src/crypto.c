#include "crypto.h"
#include <stdio.h>
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

BOOL allocate_algorithms()
{
    NTSTATUS err;

    hAesAlg = NULL;
    hShaAlg = NULL;
    hRngAlg = NULL;

    if(!NT_SUCCESS(err = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptOpenAlgorithmProvider hAesAlg\n", err);
        return FALSE;
    }

    if(!NT_SUCCESS(err = BCryptOpenAlgorithmProvider(&hRngAlg, BCRYPT_RNG_ALGORITHM, NULL, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptOpenAlgorithmProvider hRngAlg\n", err);
        return FALSE;
    }

    if(!NT_SUCCESS(err = BCryptOpenAlgorithmProvider(&hShaAlg, BCRYPT_SHA512_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
    {
        printf("**** Error 0x%lx returned by BCryptOpenAlgorithmProvider hShaAlg\n", err);
        return FALSE;
    }
    return TRUE;
}
BOOL delete_algorithms()
{
    if(hAesAlg == NULL) BCryptCloseAlgorithmProvider(hAesAlg, 0);
    if(hShaAlg == NULL) BCryptCloseAlgorithmProvider(hShaAlg, 0);
    if(hRngAlg == NULL) BCryptCloseAlgorithmProvider(hRngAlg, 0);

    return TRUE;
}
CIPHER *get_cipher_struct()
{
    CIPHER *a = (CIPHER *) HeapAlloc(GetProcessHeap(), 0, sizeof(CIPHER));
    if(a == NULL) return NULL;

    a->key_size = AES_KEY_SIZE;
    
    a->iv_size = CRYPTO_IV_SIZE;
    a->iv = NULL;

    a->key = NULL;

    a->derivation_salt = NULL;
    a->derivation_salt_size = PBKDF2_SALT_SIZE;

    a->key_object = NULL;
    a->key_object_size = 0;
    a->hKey = NULL;
    a->block_length = CRYPTO_IV_SIZE;

    return a;
}
void free_cipher_struct(CIPHER *a)
{
    if(a == NULL) return;

    if(a->key) HeapFree(GetProcessHeap(), 0, a->key);
    if(a->iv) HeapFree(GetProcessHeap(), 0, a->iv);

    if(a->hKey) BCryptDestroyKey(a->hKey);
    if(a->key_object) HeapFree(GetProcessHeap(), 0, a->key_object);

    if(a->derivation_salt) HeapFree(GetProcessHeap(), 0, a->derivation_salt);
    HeapFree(GetProcessHeap(), 0, a);
}
// IV is expected to be 16 Bytes long
BOOL create_symmetric_key_object(CIPHER *a)
{
    NTSTATUS err;
    DWORD cbData;

    // Buffer size for key object
    if(!NT_SUCCESS(err = BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PVOID) &a->key_object_size, sizeof(a->key_object_size), &cbData, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptGetProperty\n", err);
        return FALSE;
    }

    // Allocate memory for key object
    a->key_object = (PBYTE) HeapAlloc(GetProcessHeap(), 0, a->key_object_size);
    if(a->key_object == NULL)
    {
        printf("**** memory allocation failed\n");
        return FALSE;
    }

    // Buffer size for IV
    if(!NT_SUCCESS(err = BCryptGetProperty(hAesAlg, BCRYPT_BLOCK_LENGTH, (PBYTE) &a->block_length, sizeof(DWORD), &cbData, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptGetProperty\n", err);
        return FALSE;
    }

    // If IV is not given create a random one
    if(a->iv == NULL)
    {
        a->iv = get_random_bytes(a->block_length);
        a->iv_size = a->block_length;
        if(a->iv == NULL)
        {
            printf("Could not get random bytes for IV\n");
            return FALSE;
        } 
    }

    // Set property of aes
    if(!NT_SUCCESS(err = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE) BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
    {
        printf("**** Error 0x%lx returned by BCryptSetProperty\n", err);
        return FALSE;
    }

    // Create symetric key object
    if(!NT_SUCCESS(err = BCryptGenerateSymmetricKey(hAesAlg, &a->hKey, a->key_object, a->key_object_size, a->key, a->key_size, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptGenerateSymmetricKey\n", err);
        return FALSE;
    }
    return TRUE;
}

LONGLONG aes_encrypt(CIPHER *a, FILE *fp_reader, FILE *fp_writer, LONGLONG f_size)
{
    if(a == NULL || fp_reader == NULL || fp_writer == NULL ||f_size == 0) return 0;

    NTSTATUS err;
    LONGLONG cipher_size;
    DWORD bytes_encrypted;
    LONGLONG total_bytes_encrypted = 0;
    size_t bytes_read;
    BYTE buffer[CRYPTO_OUTPUT_BUFFER_SIZE];


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
    bytes_read = fread(buffer, sizeof(unsigned char), a->iv_size, fp_reader);

    // Encrypt the first block and check if it is smaller than 16 byte
    if(!NT_SUCCESS(err = BCryptEncrypt(a->hKey, buffer, (bytes_read < 16) ? bytes_read : 16, NULL, iv_copy,
                                       a->block_length, buffer, a->iv_size, &bytes_encrypted,
                                       (bytes_read < 16) ? BCRYPT_BLOCK_PADDING : 0)))
    {
        printf("**** Error 0x%lx returned by BCryptEncrypt only iv\n", err);
        return 0;
    }

    // Write the data to the file -> by writing the file pointer will be at +16 again
    fwrite(buffer, 1, bytes_encrypted, fp_writer);

    total_bytes_encrypted += bytes_encrypted;

    // Check if more than one block needs to be encrypted
    if(cipher_size > 16)
    {
        while(total_bytes_encrypted < cipher_size)
        {
            // Read data to be encrypted
            bytes_read = fread(buffer, 1, sizeof(buffer), fp_reader);

            if(!NT_SUCCESS(
                    err = BCryptEncrypt(a->hKey, buffer, bytes_read, NULL, NULL, 0, buffer, sizeof(buffer),
                                        &bytes_encrypted, (bytes_read < sizeof(buffer)) ? BCRYPT_BLOCK_PADDING : 0)))
            {
                printf("**** Error 0x%lx returned by BCryptEncrypt\n", err);
                return 0;
            }
            fwrite(buffer, sizeof(unsigned char), bytes_encrypted, fp_writer);

            total_bytes_encrypted += bytes_encrypted;
        }
    }

    HeapFree(GetProcessHeap(), 0, iv_copy);

    // Place the iv at the end of the file
    fwrite(a->iv, sizeof(unsigned char), a->iv_size, fp_writer);

    // Place the PBKDF2 salt at the end
    fwrite(a->derivation_salt, sizeof(unsigned char), a->derivation_salt_size, fp_writer);

    return total_bytes_encrypted;
}
// f_size is expected to be calculated without the iv
LONGLONG aes_decrypt(CIPHER *a, FILE *fp_reader, FILE *fp_writer, LONGLONG f_size)
{
    if(a == NULL || fp_reader == NULL || fp_writer == NULL || f_size < 16) return 0;

    NTSTATUS err;
    DWORD bytes_decrypted;
    LONGLONG total_bytes_decrypted = 0;
    size_t bytes_read;
    BYTE buffer[CRYPTO_OUTPUT_BUFFER_SIZE];

    // Read the first 16 bytes to link them with the iv and aes decrypt
    bytes_read = fread(buffer, sizeof(unsigned char), a->iv_size, fp_reader);

    // Decrypt first block with iv
    if(!NT_SUCCESS(err = BCryptDecrypt(a->hKey, buffer, bytes_read, NULL, a->iv, a->iv_size, buffer, a->iv_size,
                                       &bytes_decrypted, (f_size == a->block_length) ? BCRYPT_BLOCK_PADDING : 0)))
    {
        printf("**** Error 0x%lx returned by BCryptDecrypt only iv\n", err);
        return 0;
    }

    // write the decrypted data to the file
    fwrite(buffer, sizeof(unsigned char), bytes_decrypted, fp_writer);

    total_bytes_decrypted += bytes_decrypted;

    if(f_size > a->block_length)
    {
        do
        {
            bytes_read = fread(buffer, sizeof(unsigned char), sizeof(buffer), fp_reader);
            if(!NT_SUCCESS(
                    err = BCryptDecrypt(a->hKey, buffer, bytes_read, NULL, NULL, 0, buffer, sizeof(buffer),
                                               &bytes_decrypted, (bytes_read < sizeof(buffer)) ? BCRYPT_BLOCK_PADDING : 0)))
            {
                printf("**** Error 0x%lx returned by BCryptDecrypt\n", err);
                return 0;
            }
            fwrite(buffer, sizeof(unsigned char), bytes_decrypted, fp_writer);
            total_bytes_decrypted += bytes_decrypted;
        } while(bytes_read == sizeof(buffer));
    }
    return total_bytes_decrypted;
}

BOOL aes_encrypt_output_file(CIPHER *a, FILE *in, LONGLONG in_size, FILE *out)
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

    bytes_read = fread(buffer, sizeof(unsigned char), a->iv_size, in);

    // Encrypt the first block and check if it is smaller than 16 byte
    if(!NT_SUCCESS(err = BCryptEncrypt(a->hKey, buffer, (bytes_read < 16) ? bytes_read : 16, NULL, iv_copy,
                                       a->block_length, buffer, a->iv_size, &bytes_encrypted,
                                       (bytes_read < 16) ? BCRYPT_BLOCK_PADDING : 0)))
    {
        printf("**** Error 0x%lx returned by BCryptEncrypt only iv\n", err);
        return 0;
    }

    // Write the data to the file -> by writing the file pointer will be at +16 again
    fwrite(buffer, sizeof(unsigned char), bytes_encrypted, out);

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
            fwrite(buffer, sizeof(unsigned char), bytes_encrypted, out);
            total_bytes_encrypted += bytes_encrypted;
        }
    }

    HeapFree(GetProcessHeap(), 0, iv_copy);

    // Place the iv at the end of the file
    fwrite(a->iv, sizeof(unsigned char), a->iv_size, out);

    // Place the PBKDF2 salt at the end
    fwrite(a->derivation_salt, sizeof(unsigned char), a->derivation_salt_size, out);

    return 1;
}

BOOL aes_decrypt_output_file(CIPHER *a, FILE *in, LONGLONG in_size, FILE *out)
{
    if(a == NULL || in == NULL || out == NULL || in_size == 0) return 0;

    NTSTATUS err;
    DWORD bytes_decrypted;
    LONGLONG total_bytes_decrypted = 0;
    size_t bytes_read;
    BYTE buffer[CRYPTO_OUTPUT_BUFFER_SIZE];

    // Read the first 16 bytes to link them with the iv and aes decrypt
    bytes_read = fread(buffer, 1, a->iv_size, in);

    // Encrypt the first block and check if it is smaller than 16 byte
    if(!NT_SUCCESS(err = BCryptDecrypt(a->hKey, buffer, bytes_read, NULL, a->iv, a->iv_size, buffer, a->iv_size,
                                       &bytes_decrypted, (in_size == a->block_length) ? BCRYPT_BLOCK_PADDING : 0)))
    {
        printf("**** Error 0x%lx returned by BCryptDecrypt only iv\n", err);
        return 0;
    }

    // Write the data to the file -> by writing the file pointer will be at +16 again
    fwrite(buffer, sizeof(unsigned char), bytes_decrypted, out);

    total_bytes_decrypted += bytes_decrypted;

    // Check if there is only block to encrypt
    if(in_size > a->block_length)
    {
        do
        {
            // if sum of remaining bytes is bigger than buffer size -> read full buffer size
            if(in_size - total_bytes_decrypted > sizeof(buffer))
            {
                bytes_read = fread(buffer, sizeof(unsigned char), sizeof(buffer), in);
            }
            // else only read the remaining bytes and make sure to pad them later
            else
            {
                bytes_read = fread(buffer, sizeof(unsigned char), in_size - total_bytes_decrypted, in);
            }

            if(!NT_SUCCESS(
                    err = BCryptDecrypt(a->hKey, buffer, bytes_read, NULL, NULL, 0, buffer, sizeof(buffer),
                                        &bytes_decrypted, (bytes_read < sizeof(buffer)) ? BCRYPT_BLOCK_PADDING : 0)))
            {
                printf("**** Error 0x%lx returned by BCryptDecrypt\n", err);
                return 0;
            }
            fwrite(buffer, sizeof(unsigned char), bytes_decrypted, out);
            total_bytes_decrypted += bytes_decrypted;
        }while(bytes_read == sizeof(buffer));
    }
    return 1;
}

PBYTE get_random_bytes(DWORD count)
{
    if(count == 0) return NULL;

    NTSTATUS err;
    PBYTE buffer;

    buffer = (PBYTE) HeapAlloc(GetProcessHeap(), 0, count);
    if(buffer == NULL)
    {
        fprintf(stderr, "Could not allocate memory\n");
        return NULL;
    }

    if(!NT_SUCCESS(err = BCryptGenRandom(hRngAlg, buffer, count, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptGenRandom\n", err);
        return 0;
    }

    return buffer;
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
BOOL derive_key(PBYTE pw, DWORD pw_size, DWORD iterations, CIPHER *key_struct)
{
    if(pw == NULL || pw_size == 0 || key_struct == NULL) return FALSE;

    NTSTATUS err;

    // Allocate space for key
    key_struct->key = (PBYTE) HeapAlloc(GetProcessHeap(), 0, key_struct->key_size);
    if(key_struct->key == NULL){
        printf("**** memory allocation failed\n");
        return FALSE;
    }

    // Allocate space for salt and generate salt IF it has not already been allocated
    if(key_struct->derivation_salt == NULL)
    {
        key_struct->derivation_salt = (PBYTE) HeapAlloc(GetProcessHeap(), 0, key_struct->derivation_salt_size);
        if(key_struct->derivation_salt == NULL){
            printf("**** memory allocation failed\n");
            return FALSE;
        }
        
        if(!NT_SUCCESS(err = BCryptGenRandom(hRngAlg, key_struct->derivation_salt, key_struct->derivation_salt_size, 0)))
        {
            printf("**** Error 0x%lx returned by BCryptGenRandom\n", err);
            return FALSE;
        }
    }
    

    if(!NT_SUCCESS(err = BCryptDeriveKeyPBKDF2(hShaAlg, pw, pw_size, key_struct->derivation_salt, key_struct->derivation_salt_size, iterations, key_struct->key, key_struct->key_size, 0)))
    {
        printf("**** Error 0x%lx returned by BCryptDeriveKeyPBKDF2\n", err);
        return FALSE;
    }   
    return TRUE;
}