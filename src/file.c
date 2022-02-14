#include "file.h"

LONGLONG get_file_size(LPCSTR f_name)
{
    LARGE_INTEGER i;
    HANDLE fp = CreateFileA(f_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    GetFileSizeEx(fp, &i);
    CloseHandle(fp);
    return i.QuadPart;
}
BOOL get_iv_and_salt(LPCSTR f_name, CIPHER *a, int strip)
{
    HANDLE fp = CreateFileA(f_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(fp == INVALID_HANDLE_VALUE)
    {
        printf("Could not open file: %lu\n", GetLastError());
        return 0;
    }

    a->iv = HeapAlloc(GetProcessHeap(), 0, a->iv_size);
    if(a->iv == NULL)
    {
        printf("Could not allocate space for iv\n");
        CloseHandle(fp);
        return 0;
    }

    a->derivation_salt = HeapAlloc(GetProcessHeap(), 0, a->derivation_salt_size);
    if(a->derivation_salt == NULL)
    {
        printf("Could not allocate space for iv\n");
        CloseHandle(fp);
        return 0;
    }

    DWORD bytes_read;
    
    // Read key salt from end
    SetFilePointer(fp, - a->derivation_salt_size, 0, FILE_END);
    if(!ReadFile(fp, a->derivation_salt, a->derivation_salt_size, &bytes_read, NULL) || bytes_read != a->derivation_salt_size)
    {
        printf("Could not read derivation salt from file: %s\nbytes read: %lu\n", f_name, bytes_read);
        CloseHandle(fp);
        return 0;
    }   

    // Read iv from end of the file
    SetFilePointer(fp, - (a->iv_size +  a->derivation_salt_size), 0, FILE_END);

    if(!ReadFile(fp, a->iv, a->iv_size, &bytes_read, NULL) || bytes_read != a->iv_size)
    {
        printf("Could not read iv from file: %s\nbytes read: %lu\n", f_name, bytes_read);
        CloseHandle(fp);
        return 0;
    }
    
    SetFilePointer(fp, - a->iv_size, 0, FILE_CURRENT);

    if(strip){
        SetEndOfFile(fp);
    }

    CloseHandle(fp);
    return TRUE;
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