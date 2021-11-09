#ifndef RHINO_FILE_H
#define RHINO_FILE_H

#include "crypto.h"

LONGLONG get_file_size(LPCSTR f_name);
BOOL get_and_strip_iv(LPCSTR f_name, AES_KEY *a);
BOOL get_and_not_strip_iv(LPCSTR f_name, AES_KEY *a);
BOOL strip_file(LPCSTR f_name, int origin, long offset);

#endif
