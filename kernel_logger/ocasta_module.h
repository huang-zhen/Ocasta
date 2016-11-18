/*
 * ocasta Module
 *
 * Code derived from SNARE
 * Copyright 1999-2002 InterSect Alliance Pty Ltd
 * - http://www.intersectalliance.com/
 */

#ifndef _OCASTA_MODULE_H
#define _OCASTA_MODULE_H

#include "ocasta.h"

// #define SOLITUDE
/* #define SOLITUDE_CAPABILITIES */

/* version */
#define AUDITMODULE_MAJOR_VERSION 0
#define AUDITMODULE_MINOR_VERSION 4
#define AUDITMODULE_PATCH_VERSION 0

/* for running multiple ocasta modules simultaneously. */
/* To run a second ocasta module, comment first line, uncomment second line */
#define OCASTA_VER ""
/* #define OCASTA_VER "1" */

#define AUDIT_DEV  "audit" OCASTA_VER           /* device name in /proc */
#define AUDIT_INFO	"auditinfo" OCASTA_VER  /* device name in /proc */
#define AUDIT_SNAPSHOT  "snapshot" OCASTA_VER
#define AUDIT_DEV_FILE  "/proc/" AUDIT_DEV
#define AUDIT_SNAPSHOT_FILE  "/proc/" AUDIT_SNAPSHOT

/* ioctl modes - note that '1' doesn't seem to work */
#define AUDIT_SET_RW_DATA	  15 /* size of r/w data */
#define AUDIT_SET_MAX_READY_PAGES 16 /* Set max. nr. of ready pages */
#define AUDIT_SET_MAX_FREE_PAGES  17 /* Set max. nr. of free pages */
#define AUDIT_SEND		  18 /* setup fd and send audit data */
#define AUDIT_LOAD_AUTOCONF	  19 /* reload autoconf file */
#define AUDIT_ONOFF		  20
#define AUDIT_STOP		  21
#define AUDIT_SWITCH		  22
#define AUDIT_SET_DATA_FILE	  23 /* setup fd for file data */
#define AUDIT_SET_WORK_DIR	  24 /* set work directory */
#define AUDIT_SET_DATA_FILE_NAME  25 /* data file name */
#define AUDIT_SHOW_VERSION_LOG    26 /* show versioning logs */

/* Options for AUDIT_SET_RW_DATA */
#define AUDIT_RW_INF     0   /* Monitor unlimited amounts of r/w data */
#define AUDIT_RW_NONE    1   /* Do not monitor r/w data */
#define AUDIT_RW_SET     2   /* Monitor a set amount of r/w data */

/* Default max nr of ready pages used by the ocasta module */
#define MAX_READY_PAGES  10
/* Default max nr of free pages used by the ocasta module */
#define MAX_FREE_PAGES   1000

#define AUDIT_RW_LENGTH 20  /* The "set amount" of data to monitor */

/* some random numbers for the ioctl commands */
#define AUDIT_SNAPSHOT_STAT_CMD         0x2345
#define AUDIT_SNAPSHOT_PROC_CMD         0x2346
#define AUDIT_SNAPSHOT_STAT_UNTAINT_CMD 0x2347

#define AUDIT_SOLITUDE_START            0x2350
#define AUDIT_SOLITUDE_COMMIT           0x2351

//#define VERSIONING
//#define VERSIONING_SNAPSHOT
//#define ACCESS_REDIRECT
//#define WHITE_LIST_AUDIT
//#define SAVE_UNLINK_FILE
//#define SAVE_RENAME_FILE
#define SAVE_WRITE_DATA
#define SAVE_FILE_DATA
//#define LOG_STAT

int init_module(void);
void cleanup_module(void);

/* DO NOT use linux/version.h and LINUX_VERSION_CODE in this file */

#include <asm/types.h>

/* Customized user-space stat. */
struct custat {
        __u32 i_dev;   /* device */
        __u32 i_ino;   /* inode */
        __u16 i_mode;  /* protection */
        __u16 i_nlink; /* number of hard links */
        __u32 i_uid;   /* user ID of owner */
        __u32 i_gid;   /* group ID of owner */
        __u32 i_igen;  /* inode generation */
        __u16 i_taint; /* is file tainted bit */
	__u32 i_size;  /* size */
};

#ifdef SOLITUDE

/* some not too large number that will capture program paths */
#define SOLITUDE_PATH_LEN 252

struct ifs_capability {
        __u32 effective;
        __u32 permitted;
        __u32 inheritable;
        char name[SOLITUDE_PATH_LEN];
};

/* all ifs_capability structs should be placed right after the
 * ifs_capability_set struct */
struct ifs_capability_set {
        int nr_cap;
        /* the following fields are used in the kernel */
        int count; /* number of threads using this capability */
        struct ifs_capability *cap;
};
#endif /* SOLITUDE */

#endif /* _OCASTA_MODULE_H */
