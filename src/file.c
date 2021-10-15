#include "file.h"
#include "crypto.h"
#include <stdio.h>

BOOL read_file(LPCSTR f_name, PBYTE *f_buffer, DWORD *f_size, BOOL iv_given, DWORD iv_size, PBYTE *iv)
{
    HANDLE fp = CreateFileA(f_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(fp == INVALID_HANDLE_VALUE)
    {
        printf("Could not open file: %lu\n", GetLastError());
        return 0;
    }

    LPVOID buffer;
    DWORD size;
    size = GetFileSize(fp, NULL);

    // Calculate cipher size + iv -> this we can encrypt the data in the same buffer
    DWORD allocate_size = ((CRYPTO_IV_SIZE - (size % CRYPTO_IV_SIZE)) + size) + CRYPTO_IV_SIZE;

    buffer = HeapAlloc(GetProcessHeap(), 0, allocate_size);
    if(buffer == NULL)
    {
        printf("Could not allocate space for file buffer\n");
        CloseHandle(fp);
        return 0;
    }

    DWORD total_bytes_read = 0;
    DWORD bytes_read = 0;

    if(iv_given)
    {
        *iv = HeapAlloc(GetProcessHeap(), 0, iv_size);
        if(*iv == NULL)
        {
            CloseHandle(fp);
            HeapFree(GetProcessHeap(), 0, buffer);
            return 0;
        }
        while(total_bytes_read < iv_size)
        {
            if(!ReadFile(fp, *iv, iv_size - total_bytes_read, &bytes_read, NULL))
            {
                printf("Could not read file: %lx\n", GetLastError());
                break;
            }
            total_bytes_read += bytes_read;
        }
        // Subtract the iv
        size -= iv_size;
        total_bytes_read = 0;
    }

    while(total_bytes_read < size)
    {
        if(!ReadFile(fp, buffer, size - total_bytes_read, &bytes_read, NULL))
        {
            printf("Could not read file: %lx\n", GetLastError());
            break;
        }
        total_bytes_read += bytes_read;
    }

    *f_buffer = buffer;
    *f_size = bytes_read;

    CloseHandle(fp);
    return 1;
}
BOOL write_file(LPCSTR f_name, PBYTE buffer, DWORD count, BOOL iv_given, DWORD iv_size, PBYTE iv)
{
    HANDLE fp = CreateFileA(f_name, GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(fp == INVALID_HANDLE_VALUE)
    {
        printf("Could not open file: %lu\n", GetLastError());
        return 0;
    }

    DWORD total_bytes_written = 0;
    DWORD bytes_written = 0;

    // Write iv at the beginning of the file
    if(iv_given)
    {
        while(total_bytes_written < iv_size)
        {
            if(!WriteFile(fp, iv, iv_size - total_bytes_written, &bytes_written, 0))
            {
                printf("Could not write file: %lu\n", GetLastError());
                return 0;
            }
            total_bytes_written += bytes_written;
        }
        total_bytes_written = 0;
    }


    while(total_bytes_written < count)
    {
        if(!WriteFile(fp, buffer, count - total_bytes_written, &bytes_written, 0))
        {
            printf("Could not write file: %lu\n", GetLastError());
            return 0;
        }
        total_bytes_written += bytes_written;
    }
    CloseHandle(fp);
    return 1;
}