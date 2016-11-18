/*
 * ocasta code
 * Derived from SNARE
 * Copyright 1999-2001 InterSect Alliance Pty Ltd
 * - http://www.intersectalliance.com/
 */

#ifndef _OCASTA_H_
#define _OCASTA_H_

/* PATH_MAX in linux is 4096 but we keep it smaller here. */
#define MAX_PATH 512    

#define DEFAULT_FORENSIX_PORT 8181

/* audit classes */
enum audit_class_type
{
        AUDIT_CLASS_NONE,       /* not used */
        AUDIT_CLASS_FORK,       /* fork+ */
        AUDIT_CLASS_EXEC,       /* execve */
        AUDIT_CLASS_CHOWNMOD,   /* chown+,chmod+ */
        AUDIT_CLASS_WRITE1,     /* write+, send, truncate+ */
        AUDIT_CLASS_WRITE2,     /* sendto, sendmsg */
        AUDIT_CLASS_READ1,      /* read+, recv */
        AUDIT_CLASS_READ2,      /* recvfrom, recvmsg */
        AUDIT_CLASS_INDMAC,     /* link, symlink, rename, open+, mkdir, */
                                /* mknod, mount */
        AUDIT_CLASS_UNLINK,     /* unlink, rmdir, umount+ */
        AUDIT_CLASS_CHDIR,      /* chdir+, chroot */
        AUDIT_CLASS_MODULE,     /* create_module, init_module, delete_module */
        /* the rest of the calls have no variable length data fields */
        AUDIT_CLASS_SIGNAL,     /* kill, exit+, wait+ */
        AUDIT_CLASS_SETUGID,    /* setuid+,setgid+ */
        AUDIT_CLASS_MMAP,       /* mmap+ */
        AUDIT_CLASS_DUP,        /* dup+, fcntl, ioctl */
        AUDIT_CLASS_CONN,       /* socketcall (connect, accept) */
        AUDIT_CLASS_CLOSE,      /* close */
        AUDIT_CLASS_COMMIT,     /* SOLITUDE COMMIT calls */
        AUDIT_CLASS_SNAPSHOT,   /* send snapshot of original file */
        AUDIT_CLASS_MISC,       /* miscellaneous */
        AUDIT_CLASS_ALIGN,      /* Page alignment call */
	AUDIT_CLASS_STAT,
        AUDIT_CLASS_END         /* not used */
};

struct timeval32 {
	unsigned int tv_sec;
	unsigned int tv_usec;
};

typedef struct
{
        enum audit_class_type event_class;
        unsigned short event_id;     /* system call number */
        unsigned short event_size;   /* size of struct -  header */
        int ret;                     /* return value of syscall */
        pid_t pid;                   /* process ID */
//        unsigned int pid_time;      /* pid creation time */
        struct timeval32 time;         /* time of system call */
//        unsigned int num_blocks;     /* number of segments in data block */
        unsigned short num_blocks;     /* number of segments in data block */
        unsigned int data_size;      /* total size of data blocks */
} header_token;

/*
 * now the audit event classes. The header_token class should be the first
 * field. The len fields should follow immediately. These fields have the
 * length of each buffer attached after each class structure. For example, the
 * filename or the pwd strings are attached after the exec_class or fork_class
 * below. The filename_len and the pwd_len are the length of these strings.
 */

struct inode_nr
{
        unsigned short	dev;
        unsigned int	inode;
        unsigned int	gen;
	unsigned short	type;  /* file type: regular, symlink, dir, etc. */
};

typedef struct
{
        header_token    t_header;
        unsigned int    pwd_len;        /* current working directory */
        unsigned int    user_id;
        unsigned int    euser_id;
        unsigned int    group_id;
        unsigned int    egroup_id;
        char            comm[16];       /* command name */
        int             clone_flags;
        unsigned int   child_pid_time;
} fork_class;

typedef struct
{
        header_token    t_header;
        pid_t           t_pid;          /* Target process PID */
        unsigned int   t_pid_time;
        int             sig;            /* Signal */
        int             status;
        int             options;
} signal_class;

typedef struct
{
        header_token    t_header;
        unsigned int    ruid;
        unsigned int    euid;
        unsigned int    suid;
        unsigned int    rgid;
        unsigned int    egid;
        unsigned int    sgid;
} setugid_class;

typedef struct
{
        header_token    t_header;
        unsigned int    filename_len;
        unsigned int    arg_len;
        unsigned int    env_len;
        struct inode_nr i_nr;
        struct inode_nr parent_i_nr;
        unsigned int    ruid;
        unsigned int    euid;
        unsigned int    suid;
        unsigned int    rgid;
        unsigned int    egid;
        unsigned int    sgid;
} exec_class;

typedef struct
{
        header_token    t_header;
        unsigned int    filename_len;
        struct inode_nr i_nr;
        struct inode_nr parent_i_nr;
        unsigned int    owner;
        unsigned int    group;
        unsigned int    mode;
} chownmod_class;

typedef struct
{
        header_token    t_header;
        struct inode_nr i_nr;
        int             fd;
        int             prot;
        int             flags;
        unsigned int    len;
        int             offset;
} mmap_class;

typedef struct
{
        header_token    t_header;
        unsigned int    data_len;
        struct inode_nr i_nr;
        int             fd;
        unsigned int    len;
        int             pos;
        int             flags;
} write1_class;

typedef struct
{
        header_token    t_header;
        unsigned int    data_len;
        int             call;
        struct inode_nr i_nr;
        int             fd;
        unsigned int    udp_ip;
        unsigned short  udp_port;
        unsigned int    len;
        int             flags;
        char            isaccept;
} write2_class;

typedef struct
{
        header_token    t_header;
//        unsigned int    data_len;
        struct inode_nr i_nr;
        int             fd;
        unsigned int    len;
        int             pos;
//        int             flags;
} read1_class;

typedef struct
{
        header_token    t_header;
        unsigned int    data_len;
        int             call;
        struct inode_nr i_nr;
        int             fd;
        unsigned int    udp_ip;
        unsigned short  udp_port;
        unsigned int    len;
        int             flags;
        char            isaccept;
} read2_class;

typedef struct
{
        header_token    t_header;
        unsigned int    filename_len;
        unsigned int    source_filename_len;
        struct inode_nr i_nr;
//        struct inode_nr parent_i_nr;
//        struct inode_nr source_parent_i_nr;
        int             flags;
        unsigned int    mode;
//        unsigned int    owner;
//        unsigned int    group;
        char            isfirst;
} indmac_class;

typedef struct
{
	header_token	t_header;
	unsigned int	filename_len;
	struct inode_nr	i_nr;
} stat_class;

typedef struct
{
        header_token    t_header;
        struct inode_nr i_nr;
        int             fd;
        int             new_fd;
        int             cmd;
        int            arg;
} dup_class;

typedef struct
{
        header_token    t_header;
        struct inode_nr i_nr;
        int             call;
        int             fd;
        unsigned int    source_ip;
        unsigned short  source_port;
        unsigned int    dest_ip;
        unsigned short  dest_port;
} conn_class;

typedef struct
{
        header_token    t_header;
        unsigned int    filename_len;
        struct inode_nr i_nr;
        struct inode_nr parent_i_nr;
        char            islast;
} unlink_class;

typedef struct
{
        header_token    t_header;
        struct inode_nr i_nr;
        int             fd;
} close_class;

typedef struct
{
        header_token    t_header;
        unsigned int    filename_len;
        struct inode_nr i_nr;
        struct inode_nr parent_i_nr;
} chdir_class;

typedef struct
{
        header_token    t_header;
        unsigned int    name_len;
        unsigned int    size;
} module_class;

typedef struct
{
        header_token    t_header;
} misc_class;

typedef struct
{
        header_token    t_header;
        unsigned int    skip_len;
} page_align_class;

typedef struct
{
        header_token    t_header;
        unsigned int    skip_len; /* length to skip after this class */
        unsigned int    file_len; /* length of file */
        struct inode_nr i_nr;
        /* USED IN THE KERNEL */
        struct file    *in_file; /* use this only when it is non-NULL */
        void           *wq;   /* wait_queue_head_t pointer */
} snapshot_class;


/* Don't put any code in this file within #ifdef SOLITUDE because the backend
 * doesn't support conditional compilation */

/* max length of solitude name */
#define SOLITUDE_NAME_MAX_LEN 64

struct solitude_commit_args {
        char solitude_name[SOLITUDE_NAME_MAX_LEN];
        int commit_id;
};

typedef struct
{
        header_token    t_header;
        struct solitude_commit_args args;
} commit_class;

/* compatibility stuff */
/* DO NOT use linux/version.h and LINUX_VERSION_CODE in this file */

//#include <linux/unistd.h>

#ifdef __NR_exit_group
#define AUDIT_EXIT_GROUP
#endif

#ifndef __NR_pread
#define __NR_pread __NR_pread64
#define SYS_pread SYS_pread64
#endif

#ifndef __NR_pwrite
#define __NR_pwrite __NR_pwrite64
#define SYS_pwrite  SYS_pwrite64
#endif

#endif /* _OCASTA_H_ */
