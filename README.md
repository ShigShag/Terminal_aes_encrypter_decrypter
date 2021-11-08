# Terminal aes encryption/decryption

## Overview

This is a small terminal program to encrypt or decrypt files on the fly.  

### Usage:
```
encryption: executable -p [password] -e [Path to file] -o [Path to output file(optional)]
decryption: executable -p [password] -d [Path to file] -o [Path to output file(optional)]
```

### Compilation

This program was build with [gcc (i686-posix-dwarf-rev0, Built by MinGW-W64 project) 8.1.0](https://sourceforge.net/projects/mingw/).
but other compilers should work too.  
Make sure to link with the BCRYPT Library at compile time.

### Remarks

Encryption oder decryption without the -o option is much slower because the file is written and read at the same time.

### Platform

Windows only