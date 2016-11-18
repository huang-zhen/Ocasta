// versioning.h
#ifndef VERSIONING_H
#define VERSIONING_H

#pragma pack(1)

struct version_info {
    time_t timestamp;
    //off_t offset; // _FILE_OFFSET_BITS does not seems to affect kernel module
    size_t offset;
    size_t size;
    char extendseof;
};

#ifndef MAX_PATH
#define MAX_PATH 1024
#endif

#define VERSIONMODIFIER ".   versionfs! version"

#endif /* VERSIONING_H */
