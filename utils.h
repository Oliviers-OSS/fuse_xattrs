/*
  fuse_xattrs - Add xattrs support using sidecar files

  Copyright (C) 2016  Felipe Barriga Richards <felipe {at} felipebarriga.cl>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/


#ifndef FUSE_XATTRS_UTILS_H
#define FUSE_XATTRS_UTILS_H

#define DEBUG 1

#include <string.h>
#include <stdio.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define debug_print(fmt, ...) \
        do { \
            if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILENAME__, __LINE__, __func__, ##__VA_ARGS__); \
        } while (0)

#define error_print(fmt, ...) \
        do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILENAME__, \
                                __LINE__, __func__, ##__VA_ARGS__); } while (0)

enum namespace {
    SECURITY,
    SYSTEM,
    TRUSTED,
    USER,
    ERROR
};

enum namespace get_namespace(const char *name);
char *get_sidecar_path(const char *path);
char *sanitize_value(const char *value, size_t value_size);

#endif //FUSE_XATTRS_UTILS_H