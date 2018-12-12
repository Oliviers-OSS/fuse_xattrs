//
// Copyright (C) 2017  Felipe Barriga Richards <felipe {at} felipebarriga.cl>
//

#ifndef CMAKE_FUSE_XATTRS_CONFIG_H
#define CMAKE_FUSE_XATTRS_CONFIG_H

#define FUSE_XATTRS_VERSION_MAJOR 0
#define FUSE_XATTRS_VERSION_MINOR 3

#define BINARY_SIDECAR_EXT ".xattr"

#define MAX_METADATA_SIZE 8*1024*1024

#define XATTR_NAME_MAX 255
#define XATTR_SIZE_MAX 65536
#define XATTR_LIST_MAX 65536

#endif //CMAKE_FUSE_XATTRS_CONFIG_H
