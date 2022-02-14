#ifndef RHINO_FILE_H
#define RHINO_FILE_H

#include "crypto.h"

LONGLONG get_file_size(LPCSTR f_name);
BOOL get_iv_and_salt(LPCSTR f_name, CIPHER *a, int strip);
BOOL strip_file(LPCSTR f_name, int origin, long offset);

#endif
