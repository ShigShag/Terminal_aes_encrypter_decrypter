#ifndef RHINO_CRYPTO_H
#define RHINO_CRYPTO_H

#include <windows.h>

#define CRYPTO_IV_SIZE 16

typedef struct aes_key
{
    BCRYPT_KEY_HANDLE hKey;
    PBYTE key_object;
    DWORD key_object_size;

    PBYTE key;
    DWORD key_size;

    PBYTE iv;
    DWORD iv_size;
    DWORD block_length;

} AES_KEY;

/* ---------------------- AES ---------------------- */

/* Initialize aes algorithm, should be called at the start of the program */
BCRYPT_ALG_HANDLE initialize_aes_algorithm();

/* Initialize an aes key struct */
AES_KEY *get_aes_key_struct(PBYTE key, DWORD key_size, PBYTE iv, DWORD iv_size);

/* Free aes key struct */
void free_aes_key_struct(AES_KEY *a);

/* Create key object and set mode */
void create_symmetric_key_object(BCRYPT_ALG_HANDLE hAesAlg, AES_KEY *a);

/* Encrypt data */
BOOL aes_encrypt(AES_KEY *a, PBYTE plain, DWORD plain_size, PBYTE *cipher, DWORD *cipher_size);

/* Decrypt data */
BOOL aes_decrypt(AES_KEY *a, PBYTE cipher, DWORD cipher_size, PBYTE *plain, DWORD *plain_size);

/* ---------------------- RANDOM ---------------------- */

/* Get random bytes */
PBYTE get_random_bytes(DWORD count);

/* ---------------------- SHA ---------------------- */

BCRYPT_ALG_HANDLE initialize_sha256_algorithm();
BOOL sha256_sum(BCRYPT_ALG_HANDLE hAlg, PUCHAR plain, DWORD plain_size, PBYTE *cipher, DWORD *cipher_size);
#endif