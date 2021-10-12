#ifndef RHINO_FILE_H
#define RHINO_FILE_H

#include <windows.h>

BOOL read_file(LPCSTR f_name, PBYTE *f_buffer, DWORD *f_size, BOOL iv_given, DWORD iv_size, PBYTE *iv);
BOOL write_file(LPCSTR f_name, PBYTE buffer, DWORD count, BOOL iv_given, DWORD iv_size, PBYTE iv);



#endif
