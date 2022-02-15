#ifndef RHINO_CRYPTO_H
#define RHINO_CRYPTO_H

#include <windows.h>
#include <Bcrypt.h>
#include <stdio.h>

#define MODE_NOT_SET 0
#define MODE_ENCRYPT 1
#define MODE_DECRYPT 2
#define MODE_ENCRYPT_WITH_OUTPUT 3
#define MODE_DECRYPT_WITH_OUTPUT 4

// Maximal password length
#define MAX_PASSWORD_LENGTH 200

// IV size for aes cbc encryption
#define CRYPTO_IV_SIZE 16

// this has to be a multiple of 16
#define CRYPTO_OUTPUT_BUFFER_SIZE 1048576

// Salt length to use with PBKDF2
#define PBKDF2_SALT_SIZE 64

// Default iterations used for PBKDF2
#define PBKDF2_ITERATIONS 200000

// Aes key size
#define AES_KEY_SIZE 32

// Algorithms
BCRYPT_ALG_HANDLE hAesAlg;
BCRYPT_ALG_HANDLE hRngAlg;
BCRYPT_ALG_HANDLE hShaAlg;

typedef struct cipher
{
    BCRYPT_KEY_HANDLE hKey;
    PBYTE key_object;
    DWORD key_object_size;

    PBYTE key;
    DWORD key_size;

    PBYTE derivation_salt;
    DWORD derivation_salt_size;  

    PBYTE iv;
    DWORD iv_size;
    DWORD block_length;

    DWORD iterations;

} CIPHER;

/* ---------------------- AES ---------------------- */

/* Initialize aes algorithm, should be called at the start of the program */
BOOL allocate_algorithms();

BOOL delete_algorithms();

/* Initialize an aes key struct */
CIPHER *get_cipher_struct();

/* Free aes key struct */
VOID free_cipher_struct(CIPHER *a);

/* Create key object and set mode */
BOOL create_symmetric_key_object(CIPHER *a);

/* Encrypt data in same file*/
LONGLONG aes_encrypt(CIPHER *a, FILE *fp_reader, FILE *fp_writer, LONGLONG f_size);

/* Decrypt data in same file*/
LONGLONG aes_decrypt(CIPHER *a, FILE *fp_reader, FILE *fp_writer, LONGLONG f_size);

/* Encrypt data with output file */
BOOL aes_encrypt_output_file(CIPHER *a, FILE *in, LONGLONG in_size, FILE *out);

/* Decrypt data with output file */
BOOL aes_decrypt_output_file(CIPHER *a, FILE *in, LONGLONG in_size, FILE *out);

/* ---------------------- RANDOM ---------------------- */

/* Get random bytes */
PBYTE get_random_bytes(DWORD count);

/* ---------------------- KEY ---------------------- */

/* Password input */
PBYTE getpass(const char *prompt, int *pw_size);

/* Key derivation */
BOOL derive_key(PBYTE pw, DWORD pw_size, DWORD iterations, CIPHER *key_struct);

#endif