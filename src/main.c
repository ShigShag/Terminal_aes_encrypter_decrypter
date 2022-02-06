#include <stdio.h>
#include "crypto.h"
#include "file.h"

#define MODE_NOT_SET 0
#define MODE_ENCRYPT 1
#define MODE_DECRYPT 2
#define MODE_ENCRYPT_WITH_OUTPUT 3
#define MODE_DECRYPT_WITH_OUTPUT 4

void print_help()
{
    printf("Usage: executable -p [password] -(e/d) [Path to file]\n optional\n-o [output file]\n");
}
int main(int argc, char *argv[])
{
    if(argc < 5){
        print_help();
        return 0;
    }

    int mode;
    int pw_set = 0;

    LPCSTR pw;
    LPCSTR path;
    LPCSTR output_path;

    FILE *in_file = NULL;
    FILE *out = NULL;

    PBYTE hash;
    DWORD hash_size;
    BCRYPT_ALG_HANDLE sha256_alg;

    BCRYPT_ALG_HANDLE aes_algorithm;

    AES_KEY *aes_key;

    LONGLONG plain_size;
    LONGLONG f_size;

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
            break;
        }
    }

    output_path = path;

    for(int i = 0;i < argc;i++)
    {
        if(strcmp(argv[i], "-p") == 0 && i != argc - 1){
            pw = argv[i + 1];
            pw_set = 1;
            break;
        }
    }

    for(int i = 0;i < argc;i++)
    {
        if(strcmp(argv[i], "-o") == 0 && i != argc - 1){
            output_path = argv[i + 1];
            switch(mode)
            {
                case MODE_ENCRYPT:
                    mode = MODE_ENCRYPT_WITH_OUTPUT;
                    break;

                case MODE_DECRYPT:
                    mode = MODE_DECRYPT_WITH_OUTPUT;
                    break;

                default:
                    mode = MODE_NOT_SET;
                    break;
            }
            break;
        }
    }

    // Check if output and path are the same
    if(strcmp(path, output_path) == 0)
    {
        if(mode == MODE_DECRYPT_WITH_OUTPUT) mode = MODE_DECRYPT;
        else if(mode == MODE_ENCRYPT_WITH_OUTPUT) mode = MODE_ENCRYPT;
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
    aes_key = get_aes_key_struct(hash, hash_size);
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

    // Get and strip iv from the end of the file
    if(mode == MODE_DECRYPT)
    {
        if(get_and_strip_iv(path, aes_key) == 0)
        {
            goto Cleanup;
        }
    }
    else if(mode == MODE_DECRYPT_WITH_OUTPUT)
    {
        if(get_and_not_strip_iv(path, aes_key) == 0)
        {
            goto Cleanup;
        }
    }

    f_size = get_file_size(path);

    in_file = fopen(path, "rb+");
    if(in_file == NULL)
    {
        fprintf(stderr, "Could not open file\n");
        goto Cleanup;
    }

    if(mode == MODE_ENCRYPT)
    {
        FILE *in_file_writer = fopen(path, "rb+");
        if(in_file_writer == NULL)
        {
            fprintf(stderr, "Could not open the file for writing\n");
            goto Cleanup;
        } 

        plain_size = aes_encrypt(aes_key, in_file, in_file_writer, f_size);
        fclose(in_file);
        in_file = NULL;
        fclose(in_file_writer);
        if(plain_size == 0)
        {
            fprintf(stderr, "Could not aes encrypt the file\n");
            goto Cleanup;
        }
        printf("File was encrypted\n");
    }else if(mode == MODE_DECRYPT)
    {
        FILE *in_file_writer = fopen(path, "rb+");
        if(in_file_writer == NULL)
        {
            fprintf(stderr, "Could not open the file for writing\n");
            goto Cleanup;
        } 
        plain_size = aes_decrypt(aes_key, in_file, in_file_writer, f_size);
        fclose(in_file);
        in_file = NULL;
        fclose(in_file_writer);
        if(plain_size == 0)
        {
            fprintf(stderr, "Could not decrypt the file\n");
            goto Cleanup;
        }

        // Strip remains of the encrypted file
        strip_file(path, FILE_END, - (f_size - plain_size));

        printf("File was decrypted\n");
    }
    else if(mode == MODE_ENCRYPT_WITH_OUTPUT)
    {
        out = fopen(output_path, "wb");
        if(out == NULL)
        {
            fprintf(stderr, "Could not open output file: %s\n", output_path);
            goto Cleanup;
        }
        plain_size = aes_encrypt_output_file(aes_key, in_file, f_size, out);
        if(plain_size == 0)
        {
            fprintf(stderr, "Could not decrypt the file\n");
            goto Cleanup;
        }
        printf("File was encrypted\n");
    }
    else if(mode == MODE_DECRYPT_WITH_OUTPUT)
    {
        // Exclude the iv at the of the file
        f_size -= 16;
     
        out = fopen(output_path, "wb");
        if(out == NULL)
        {
            fprintf(stderr, "Could not open output file: %s\n", output_path);
            goto Cleanup;
        }
        plain_size = aes_decrypt_output_file(aes_key, in_file, f_size, out);
        if(plain_size == 0)
        {
            fprintf(stderr, "Could not decrypt the file\n");
            goto Cleanup;
        }
        printf("File was decrypted\n");

    }

    // Free everything
    Cleanup:
    if(aes_key) free_aes_key_struct(aes_key);
    if(aes_algorithm) BCryptCloseAlgorithmProvider(aes_algorithm, 0);
    if(in_file) fclose(in_file);
    if(out) fclose(out);

    return 0;
}
