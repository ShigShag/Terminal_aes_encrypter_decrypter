#include <stdio.h>
#include "crypto.h"
#include "file.h"

#define MODE_NOT_SET 0
#define MODE_ENCRYPT 1
#define MODE_DECRYPT 2

void print_help()
{
    printf("Usage: rhino -p [password] -(e/d) [Path to file]\n");
}
int main(int argc, char *argv[])
{
    if(argc < 5){
        print_help();
        return 0;
    }

    int mode;
    int pw_set = 0;
    BOOL iv_given = 0;
    LPCSTR pw;
    LPCSTR path;

    NTSTATUS err;

    PBYTE hash;
    DWORD hash_size;
    BCRYPT_ALG_HANDLE sha256_alg;

    BCRYPT_ALG_HANDLE aes_algorithm;

    AES_KEY *aes_key;

    PBYTE plain = NULL;
    DWORD plain_size;

    PBYTE cipher = NULL;
    DWORD cipher_size;

    for(int i = 0;i < argc;i++)
    {
        if(strcmp(argv[i], "-e") == 0 && i != argc - 1){
            mode = MODE_ENCRYPT;
            path = argv[i + 1];
            break;
        }
        if(strcmp(argv[i], "-d") == 0 && i != argc - 1){
            mode = MODE_DECRYPT;
            path = argv[i + 1];
            iv_given = 1;
            break;
        }
    }

    for(int i = 0;i < argc;i++)
    {
        if(strcmp(argv[i], "-p") == 0 && i != argc - 1){
            pw = argv[i + 1];
            pw_set = 1;
            break;
        }
    }

    if(!pw_set)
    {
        printf("Password was not set\n");
        print_help();
        return 0;
    }
    if(mode == MODE_NOT_SET)
    {
        printf("Mode was not set\n");
        print_help();
        return 0;
    }

    // Create Hash from password
    sha256_alg = initialize_sha256_algorithm();
    if(sha256_alg == NULL) goto Cleanup;
    sha256_sum(sha256_alg, (PUCHAR) pw, strlen(pw), &hash, &hash_size);

    // Initialize aes
    aes_algorithm = initialize_aes_algorithm();
    if(!aes_algorithm) goto Cleanup;
    aes_key = get_aes_key_struct(hash, hash_size, NULL, CRYPTO_IV_SIZE);
    if(!aes_key)
    {
        fprintf(stderr, "Could not set aes key struct\n");
        goto Cleanup;
    }

    // Free hash
    HeapFree(GetProcessHeap(), 0, hash);
    BCryptCloseAlgorithmProvider(sha256_alg, 0);

    // Create symmetric key
    create_symmetric_key_object(aes_algorithm, aes_key);

    // Read file
    plain = NULL;
    err = read_file(path, &plain, &plain_size, iv_given, aes_key->iv_size, &aes_key->iv);
    if(!err)
    {
        fprintf(stderr, "Could not read the file\n");
        goto Cleanup;
    }

    // Encrypt data
    if(mode == MODE_ENCRYPT)
    {
        cipher = NULL;
        err = aes_encrypt(aes_key, plain, plain_size, &cipher, &cipher_size);
        if(!err)
        {
            fprintf(stderr, "Could not aes encrypt the file\n");
            goto Cleanup;
        }

        err = write_file(path, cipher, cipher_size, 1, aes_key->iv_size, aes_key->iv);
        if(!err)
        {
            fprintf(stderr, "Could not write to the file\n");
            goto Cleanup;
        }
    }else if(mode == MODE_DECRYPT)
    {
        cipher = NULL;
        err = aes_decrypt(aes_key, plain, plain_size, &cipher, &cipher_size);
        if(!err)
        {
            fprintf(stderr, "Could not decrypt the file\n");
            goto Cleanup;
        }

        err = write_file(path, cipher, cipher_size, 0, aes_key->iv_size, aes_key->iv);
        if(!err)
        {
            fprintf(stderr, "Could not write to the file\n");
            goto Cleanup;
        }
    }

    Cleanup:
    // Free everything
    if(plain) HeapFree(GetProcessHeap(), 0, plain);
    if(cipher) HeapFree(GetProcessHeap(), 0, cipher);
    if(aes_key) free_aes_key_struct(aes_key);
    if(aes_algorithm) BCryptCloseAlgorithmProvider(aes_algorithm, 0);

    return 0;
}
