#include "file.h"

DWORD get_file_size(LPCSTR f_name)
{
    HANDLE fp = CreateFileA(f_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD size = GetFileSize(fp, NULL);
    CloseHandle(fp);
    return size;
}
BOOL get_and_strip_iv(LPCSTR f_name, AES_KEY *a)
{
    HANDLE fp = CreateFileA(f_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(fp == INVALID_HANDLE_VALUE)
    {
        printf("Could not open file: %lu\n", GetLastError());
        return 0;
    }

    a->iv = HeapAlloc(GetProcessHeap(), 0, CRYPTO_IV_SIZE);
    if(a->iv == NULL)
    {
        printf("Could not allocate space for iv\n");
        CloseHandle(fp);
        return 0;
    }

    SetFilePointer(fp, - CRYPTO_IV_SIZE, 0, FILE_END);

    // Read iv from end of the file
    DWORD bytes_read;
    if(!ReadFile(fp, a->iv, CRYPTO_IV_SIZE, &bytes_read, NULL) || bytes_read != CRYPTO_IV_SIZE)
    {
        printf("Could not read iv from file: %s\nbytes read: %lu\n", f_name, bytes_read);
        CloseHandle(fp);
        return 0;
    }

    // Remove iv from end of the file
    SetFilePointer(fp, - CRYPTO_IV_SIZE, 0, FILE_END);
    SetEndOfFile(fp);

    CloseHandle(fp);
    return 1;
}
BOOL get_and_not_strip_iv(LPCSTR f_name, AES_KEY *a)
{
    HANDLE fp = CreateFileA(f_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(fp == INVALID_HANDLE_VALUE)
    {
        printf("Could not open file: %lu\n", GetLastError());
        return 0;
    }

    a->iv = HeapAlloc(GetProcessHeap(), 0, CRYPTO_IV_SIZE);
    if(a->iv == NULL)
    {
        printf("Could not allocate space for iv\n");
        CloseHandle(fp);
        return 0;
    }

    SetFilePointer(fp, - CRYPTO_IV_SIZE, 0, FILE_END);

    // Read iv from end of the file
    DWORD bytes_read;
    if(!ReadFile(fp, a->iv, CRYPTO_IV_SIZE, &bytes_read, NULL) || bytes_read != CRYPTO_IV_SIZE)
    {
        printf("Could not read iv from file: %s\nbytes read: %lu\n", f_name, bytes_read);
        CloseHandle(fp);
        return 0;
    }

    CloseHandle(fp);
    return 1;
}
BOOL strip_file(LPCSTR f_name, int origin, long offset)
{
    HANDLE fp = CreateFileA(f_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(fp == INVALID_HANDLE_VALUE)
    {
        printf("Could not open file in strip_file: %lu\n", GetLastError());
        return 0;
    }

    SetFilePointer(fp, offset, 0, origin);
    SetEndOfFile(fp);
    CloseHandle(fp);
    return 1;
}