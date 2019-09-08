/*
  fuse_xattrs - Add xattrs support using sidecar files

  Copyright (C) 2016  Felipe Barriga Richards <felipe {at} felipebarriga.cl>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/


#ifndef FUSE_XATTRS_UTILS_H
#define FUSE_XATTRS_UTILS_H

#include <sys/types.h>
#include <sys/fsuid.h>
#include <string.h>
#include <stdio.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <fuse.h>
#include <unistd.h>

#include "debug.h"

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
char *prepend_source_directory(const char *b);

const size_t BINARY_SIDECAR_EXT_SIZE;
const int filename_is_sidecar(const char *string);

int is_directory(const char *path);
int is_regular_file(const char *path);

static inline struct fuse_context *setCallerIdentity() {
	/* Get user context from fuse framework */
	struct fuse_context *context = fuse_get_context();
	if (likely(context)) {
		/* Set uid and primary group id to use for file system access */
		const uid_t uid = context->uid;
		setfsgid(context->gid);
		setfsuid(uid);
		/* Set supplementary user group */
		struct passwd* usr_pwd_ctx = getpwuid(uid);
		if (likely( usr_pwd_ctx != NULL )) {
			gid_t usr_grp[NGROUPS_MAX];
			int nb_grp=sizeof(usr_grp)/sizeof(usr_grp[0]);
			int ret = getgrouplist(usr_pwd_ctx->pw_name, context->gid, usr_grp, &nb_grp);
			if (likely( ret != -1 )) {
				setgroups(nb_grp, usr_grp);
			} else {
				ERROR_MSG("User %d has more than %d supplementary groups", uid, NGROUPS_MAX);
			}
		} else {
			ERROR_MSG("Fail to get passwd context for user %d", context->uid);
		}
	} else {
		ERROR_MSG("Fail to get fuse context");
	}
	return context;
}
#endif //FUSE_XATTRS_UTILS_H
