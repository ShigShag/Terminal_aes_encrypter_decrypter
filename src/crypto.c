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
AES_KEY *get_aes_key_struct(PBYTE key, DWORD key_size, PBYTE iv, DWORD iv_size)
{
    AES_KEY *a = (AES_KEY *) HeapAlloc(GetProcessHeap(), 0, sizeof(AES_KEY));
    if(a == NULL) return NULL;

    a->key_size = key_size;
    a->iv_size = iv_size;

    a->iv = NULL;
    a->key = NULL;

    if(key != NULL && a->key_size > 0)
    {
        a->key = HeapAlloc(GetProcessHeap(), 0, a->key_size);
        memcpy(a->key, key, a->key_size);
    }
    if(iv != NULL && a->iv_size > 0)
    {
        a->iv = HeapAlloc(GetProcessHeap(), 0, a->iv_size);
        memcpy(a->iv, iv, a->iv_size);
    }
    a->key_object = NULL;
    a->key_object_size = 0;
    a->hKey = NULL;
    a->block_length = 0;

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
    //printf("[+] Got iv size: %lu\n", a->block_length);

    if(a->iv != NULL && a->iv_size < a->block_length)
    {
        printf("Iv size is too small: %lu needed at least: %lu\n", a->iv_size, a->block_length);
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
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", err);
        return;
    }
    //printf("[+] Created symmetric key\n");
}
BOOL aes_encrypt(AES_KEY *a, PBYTE plain, DWORD plain_size, PBYTE *cipher, DWORD *cipher_size)
{
    if(a == NULL || plain == NULL || plain_size == 0) return 0;

    NTSTATUS err;
    DWORD cbData;

    // Get size of cipher text
    if(!NT_SUCCESS(err = BCryptEncrypt(a->hKey, plain, plain_size, NULL, a->iv, a->block_length, NULL, 0, cipher_size, BCRYPT_BLOCK_PADDING)))
    {
        printf("**** Error 0x%lx returned by BCryptEncrypt\n", err);
        return 0;
    }

    *cipher = (PBYTE) HeapAlloc(GetProcessHeap(), 0, *cipher_size);
    if(*cipher == NULL)
    {
        printf("Could not allocate space for cipher\n");
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

    if(!NT_SUCCESS(err = BCryptEncrypt(a->hKey, plain, plain_size, NULL, iv_copy, a->block_length, *cipher, *cipher_size, &cbData, BCRYPT_BLOCK_PADDING)))
    {
        printf("**** Error 0x%lx returned by BCryptEncrypt\n", err);
        return 0;
    }

    HeapFree(GetProcessHeap(), 0, iv_copy);
    return 1;
}
BOOL aes_decrypt(AES_KEY *a, PBYTE cipher, DWORD cipher_size, PBYTE *plain, DWORD *plain_size)
{
    if(a == NULL || cipher == NULL || cipher_size == 0) return 0;

    NTSTATUS err;
    DWORD output_buffer_size;

    // Get size of plain text
    if(!NT_SUCCESS(err = BCryptDecrypt(a->hKey, cipher, cipher_size, NULL, a->iv, a->block_length, NULL, 0, &output_buffer_size, BCRYPT_BLOCK_PADDING)))
    {
        printf("**** Error 0x%lx returned by BCryptEncrypt\n", err);
        return 0;
    }

    *plain = (PBYTE) HeapAlloc(GetProcessHeap(), 0, output_buffer_size);
    if(*plain == NULL)
    {
        printf("Could not allocate space for cipher\n");
        return 0;
    }
    if(!NT_SUCCESS(err = BCryptDecrypt(a->hKey, cipher, cipher_size, NULL, a->iv, a->block_length, *plain, output_buffer_size, plain_size, BCRYPT_BLOCK_PADDING)))
    {
        printf("**** Error 0x%lx returned by BCryptEncrypt\n", err);
        return 0;
    }

    return 1;
}
PBYTE get_random_bytes(DWORD count)
{
    if(count == 0) return NULL;

    BCRYPT_ALG_HANDLE h;
    NTSTATUS err;
    PBYTE buffer;

    err = BCryptOpenAlgorithmProvider(&h, BCRYPT_RNG_ALGORITHM, NULL, 0);

    buffer = (PBYTE) HeapAlloc(GetProcessHeap(), 0, count);
    if(buffer == NULL)
    {
        fprintf(stderr, "Could not allocate memory\n");
        return NULL;
    }

    BCryptGenRandom(h, buffer, count, 1);
    BCryptCloseAlgorithmProvider(h, 0);
    return buffer;
}
BCRYPT_ALG_HANDLE initialize_sha256_algorithm()
{
    NTSTATUS err;
    BCRYPT_ALG_HANDLE hAesAlg;

    if(!NT_SUCCESS(err = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", err);
        return NULL;
    }
    //printf("[+] Created sha256 algorithm handle\n");
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





























