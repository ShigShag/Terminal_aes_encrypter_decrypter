#include <stdio.h>
#include "crypto.h"
#include "file.h"
#include "test.h"

void print_help()
{
    printf("Usage: executable -p [password] -(e/d) [Path to file]\n optional\n-o [output file]\n");
}
int main(int argc, char *argv[])
{
    int mode;
    int pw_set = 0;
    
    PBYTE pw;
    LPCSTR path;
    LPCSTR output_path;

    FILE *in_file = NULL;
    FILE *out = NULL;

    DWORD iterations = PBKDF2_ITERATIONS;

    BCRYPT_ALG_HANDLE aes_algorithm;

    CIPHER *cypher_struct;

    LONGLONG plain_size;
    LONGLONG f_size;

    // Search for iterations for PBKDF2
    for(int i = 0;i < argc;i++)
    {
        if(strcmp(argv[i], "-i") == 0 && i != argc - 1){
            iterations = strtol(argv[i + 1], NULL, 10);
            break;
        }
    }

    // Search for test mode
    for(int i = 0;i < argc;i++)
    {
        if(strcmp(argv[i], "-t") == 0){
            run_test(iterations);
            return 0;
        }
    }

    // Search for mode and path
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

    // Search for output file or same file
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

    if(allocate_algorithms() == FALSE){
        return 0;
    }

    // Try to allocate algorithms
    if((cypher_struct = get_cipher_struct()) == NULL) goto CLEANUP;

    // Get and strip iv from the end of the file
    if(mode == MODE_DECRYPT)
    {
        if(get_iv_and_salt(path, cypher_struct, 1) == 0)
        {
            goto CLEANUP;
        }
    }
    else if(mode == MODE_DECRYPT_WITH_OUTPUT)
    {
        if(get_iv_and_salt(path, cypher_struct, 0) == 0)
        {
            goto CLEANUP;
        }
    }

    // Derive the key
    if(!derive_key(pw, strlen(pw), iterations, cypher_struct)) goto CLEANUP;


    // Create symmetric key
    if(!create_symmetric_key_object(cypher_struct)) goto CLEANUP;

    f_size = get_file_size(path);

    in_file = fopen(path, "rb+");
    if(in_file == NULL)
    {
        fprintf(stderr, "Could not open file\n");
        goto CLEANUP;
    }

    // printf("PBKDF2 salt\n");
    // for(int i = 0;i < cypher_struct->derivation_salt_size;i++){
    //     printf("%.2x ", cypher_struct->derivation_salt[i]);
    // }

    // printf("\nIV\n");
    // for(int i = 0;i < cypher_struct->iv_size;i++){
    //     printf("%.2x ", cypher_struct->iv[i]);
    // }
    
    // printf("\nKey\n");
    // for(int i = 0;i < cypher_struct->key_size;i++){
    //     printf("%.2x ", cypher_struct->key[i]);
    // }
    // printf("\n");

    if(mode == MODE_ENCRYPT)
    {
        FILE *in_file_writer = fopen(path, "rb+");
        if(in_file_writer == NULL)
        {
            fprintf(stderr, "Could not open the file for writing\n");
            goto CLEANUP;
        } 

        plain_size = aes_encrypt(cypher_struct, in_file, in_file_writer, f_size);
        fclose(in_file);
        in_file = NULL;
        fclose(in_file_writer);
        if(plain_size == 0)
        {
            fprintf(stderr, "Could not aes encrypt the file\n");
            goto CLEANUP;
        }
        printf("File was encrypted\n");
    }else if(mode == MODE_DECRYPT)
    {
        FILE *in_file_writer = fopen(path, "rb+");
        if(in_file_writer == NULL)
        {
            fprintf(stderr, "Could not open the file for writing\n");
            goto CLEANUP;
        } 
        plain_size = aes_decrypt(cypher_struct, in_file, in_file_writer, f_size);
        fclose(in_file);
        in_file = NULL;
        fclose(in_file_writer);
        if(plain_size == 0)
        {
            fprintf(stderr, "Could not decrypt the file\n");
            goto CLEANUP;
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
            goto CLEANUP;
        }
        plain_size = aes_encrypt_output_file(cypher_struct, in_file, f_size, out);
        if(plain_size == 0)
        {
            fprintf(stderr, "Could not decrypt the file\n");
            goto CLEANUP;
        }
        printf("File was encrypted\n");
    }
    else if(mode == MODE_DECRYPT_WITH_OUTPUT)
    {
        // Exclude the iv and the salt to preserve file integrity
        f_size -= CRYPTO_IV_SIZE + PBKDF2_SALT_SIZE;
     
        out = fopen(output_path, "wb");
        if(out == NULL)
        {
            fprintf(stderr, "Could not open output file: %s\n", output_path);
            goto CLEANUP;
        }
        plain_size = aes_decrypt_output_file(cypher_struct, in_file, f_size, out);
        if(plain_size == 0)
        {
            fprintf(stderr, "Could not decrypt the file\n");
            goto CLEANUP;
        }
        printf("File was decrypted\n");

    }

    // Free everything
    CLEANUP:
    if(cypher_struct) free_cipher_struct(cypher_struct);
    delete_algorithms();
    if(in_file) fclose(in_file);
    if(out) fclose(out);

    return 0;
}
