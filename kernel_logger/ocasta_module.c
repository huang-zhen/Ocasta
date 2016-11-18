/*
 * This code is derived from SNARE.
 *
 * Copyright 1999-2002 InterSect Alliance Pty Ltd - 
 * http://www.intersectalliance.com/
 * Copyright 2002 Redhat Pty Ltd - http://www.redhat.com/
 *
 * This module sits in the kernel and monitors system call information.
 */

#define _FILE_OFFSET_BITS 64

#include <linux/version.h>

#ifdef MODVERSIONS
/* reload modversions.h
 * this code is here to deal with Redhat 2.4 kernels */
#undef _LINUX_MODVERSIONS_H
#include <linux/modversions.h>
#endif /* MODVERSIONS */

#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/in.h>
#include <linux/pagemap.h>
#include <linux/mman.h>
#include <net/sock.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/ptrace.h>
#include <net/ip.h>
#include <asm/byteorder.h>
#endif /* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#define TASKLIST_LOCK rcu_read_lock()
#define TASKLIST_UNLOCK rcu_read_unlock()
#else  /* LINUX_VERSION_CODE */
#define TASKLIST_LOCK read_lock_irq(&tasklist_lock)
#define TASKLIST_UNLOCK read_unlock_irq(&tasklist_lock)
#endif /* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#include <linux/fs_struct.h>
#endif

#include <linux/time.h>
#include <linux/dirent.h>

#define USE_NETLINK

#ifdef USE_NETLINK
#include <linux/netlink.h>
#endif

#include "ocasta_dat.h"
#include "ocasta_module.h"

#ifdef VERSIONING
#include "versioning.h"
#endif

MODULE_AUTHOR("James Huang, Ashvin Goel, Mike Shea (UofT and OGI)");
MODULE_DESCRIPTION("4N6 Audit Module");

#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

static int logging = 1;
module_param(logging, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(logging, "Logging enabled(1)/disabled(0) to backend");

/* debugging stuff */
#include <linux/kernel.h>
#define ASSERT_AUDIT(x)  if (!(x)) { \
          panic(KERN_EMERG "assertion failed at %s:%d: %s\n", __FILE__, \
          __LINE__, #x); }
//#define JUST_EXEC
//#define DEBUG_AUDIT
#define AUDIT_EXIT_GROUP
//#define SOLITUDE_AUDIT

#ifdef DEBUG_AUDIT
/* print audit debug (printad) */
#define printad(str, args...) printk(str, ## args)
#else
#define printad(str, args...)
#endif /* DEBUG_AUDIT */


#ifdef SOLITUDE_AUDIT
/* print solitude audit debug (printas) */
#define printas(str, args...) printk(str, ## args)
#else
#define printas(str, args...)
#endif /* SOLITUDE_AUDIT */

/* compatibility stuff */

#ifdef DEFINE_WAIT
#define sleep_for(wq, time) { \
DEFINE_WAIT(wait);\
prepare_to_wait(wq, &wait, TASK_UNINTERRUPTIBLE); \
schedule_timeout(time); \
finish_wait(wq, &wait); \
}
#else /* DEFINE_WAIT */
#define sleep_for(wq, time) sleep_on_timeout(wq, time)
#endif /* DEFINE_WAIT */

/* copied because it's __inline__ in socket.c */
#ifndef sockfd_put
#define sockfd_put(sock) fput((sock)->file)     
#endif /* sockfd_put */

#ifndef min_t
#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#endif /* min_t */

#ifndef likely
#define likely(x) x
#endif /* likely */

#ifndef __user
#define __user
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)

#define inet_sk(x) (x)
#define GET_INODE_IDEV(i) ((i)->i_dev)

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#define GET_INODE_IDEV(i) kdev_t_to_nr((i)->i_sb->s_dev)

#else

#define GET_INODE_IDEV(i) old_encode_dev((i)->i_sb->s_dev)

#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,4,7)
static inline void list_move_tail(struct list_head *list,
				  struct list_head *head)
{
        __list_del(list->prev, list->next);
        list_add_tail(list, head);
}
#endif /* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,0)
#define PROCESS_START_TIME(p) (p)->start_time
#else
#define PROCESS_START_TIME(p) (p)->start_time.tv_sec
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,4,2)
#define sendpage writepage
#endif /* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) && defined(CONFIG_KALLSYMS)
#define GET_SYMBOL
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
static int change_page_attr_ex(struct page *page, int numpages, pgprot_t prot);
#else
static inline int change_page_attr_set(unsigned long addr, int numpages,
				       pgprot_t mask);
#endif

/* deal with symbols that are not exported anymore */
static int (*do_execve_fn)(char *, char **, char **, struct pt_regs *) = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
static pte_t *(*lookup_address_fn)(unsigned long, unsigned int *) = NULL;
#else
static pte_t *(*lookup_address_fn)(unsigned long) = NULL;
#endif

#ifdef SOLITUDE
static struct super_operations *ext3_sops_fn = NULL;
#endif /*SOLITUDE*/
static ssize_t (*do_sendfile_fn)(int, int, loff_t*, size_t, loff_t) = NULL;

/* keep this part of sys_exeve up-to-date with different versions of Linux */
#define POST_EXECVE() if (error == 0) { \
		task_lock(current); \
                current->ptrace &= ~PT_DTRACE; \
		task_unlock(current); \
		/* Make sure we don't return using sysenter.. */ \
		set_thread_flag(TIF_IRET); \
	} \

#define ISACCEPT_MASK 0x80000000U

#ifdef SOLITUDE

#define TAINTED_PROCESS_MASK 0x01000000
#define IFS_PROCESS_MASK     0x02000000
/* TODO: change the value */
#define TAINTED_FILE_MASK 0x800000
#define TESTBIT 0x200000
#define IFSBIT 0x400000

#define process_in_ifs() \
((current->flags & IFS_PROCESS_MASK) == IFS_PROCESS_MASK)

/* process should not be in IFS */
#define process_is_tainted() \
((current->flags & \
(IFS_PROCESS_MASK | TAINTED_PROCESS_MASK)) == TAINTED_PROCESS_MASK)

#define file_is_ext3(inode) ((inode)->i_sb->s_op == ext3_sops_fn)

/* don't use directly */
#define _file_is_tainted(inode) \
((EXT3_I(inode)->i_flags & TAINTED_FILE_MASK) == TAINTED_FILE_MASK)

/* file should be in ext3 */

/* do not negate these macros */
#define file_is_tainted(inode) (file_is_ext3(inode) && \
_file_is_tainted(inode))
#define file_is_untainted(inode) (file_is_ext3(inode) && \
!_file_is_tainted(inode))

#endif /* SOLITUDE */

#ifdef USE_NETLINK
#define WAKEUP_COND (((auditdata.nr_ready_pages >= \
                             auditdata.max_ready_pages) || \
            ((auditdata.force || atomic_read(&auditdata.sendfile_active)) && \
             auditdata.nr_ready_pages > 0)) && \
	     auditdata.rcvpid)
#else
#define WAKEUP_COND ((auditdata.nr_ready_pages >= \
                             auditdata.max_ready_pages) || \
            ((auditdata.force || atomic_read(&auditdata.sendfile_active)) && \
             auditdata.nr_ready_pages > 0))
#endif

struct pgnode {
        struct list_head list; /* list of pages holding data */
        atomic_t count;        /* count of allocations */
        struct page *page;
#ifdef SOLITUDE
        int marker_flag;       /* mark for snapshot header class */ 
#endif /* SOLITUDE */
};

struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[1];
};

#define SHADOW_DIR ".dir"

struct auditevent {
        struct pgnode *node;   /* pgnode holding the event */
        int offset;            /* offset in pgnode holding event */
        int size;              /* total size of data allocation */
        int try_sending_pages;     /* should we call audit_try_sending_pages */
};

struct auditdata_global {
        struct task_struct *task;         /* task struct of sending thread */
        struct file *fp;                  /* output file pointer */
        int fd;                           /* fd associated with fp above */
        struct file *datafp;              /* data file pointer */
	int datafd;			  /* fd associated with datafp */
	int dataseq;			  /* data file entry seq number */
#ifdef USE_NETLINK
	struct sock *nl_sk;		  /* NETLINK socket */
	pid_t rcvpid;			  /* NETLINK receiver pid */
#endif
	char work_dir[MAX_PATH];	  /* work directory */
	char shadow_dir[MAX_PATH];	  /* shadow directory */
	int shadow_dir_len;		  /* length of the above string */
	char data_file_name[MAX_PATH]; 	  /* data file name */
        int rw_type;                      /* type of r/w monitoring */
        int sending_active;               /* is data being sent? */

        volatile int max_ready_pages;     /* max nr of pages ready/sending */
        volatile int nr_ready_pages;      /* nr of pages ready to be sent */
        volatile int force;               /* force sending data */
	volatile int stop;		  /* force stop */

        int max_free_pages;               /* max nr of free pages */
        int nr_free_pages;                /* stats: nr of free pages */
        int nr_active_pages;              /* stats: nr of pages being written */
        int nr_send_pages;                /* nr of pages being sent */
        int nr_allocated_pages;           /* total number of pages
                                           * allocated by ocasta */
        struct list_head free_list;       /* list of free pages */
        struct list_head active_list;     /* list of pages being written */
        struct list_head ready_list;      /* list of pages ready to send */
        struct list_head send_list;       /* list of pages being sent */
        struct pgnode *alloc_pgnode;      /* pgnode for next allocation */
        int alloc_pos;                    /* position for next alloc */

        atomic_t sendfile_active;         /* is send_original_file active?
                                           * Currently, only used in
                                           * SOLITUDE code. */
	int audit_mode;
	int show_shadow_dir;		  /* allow viewing shadow directory */
	int show_version_log;		  /* allow viewing versioning log */
};

static struct auditdata_global auditdata; /* Global data */

static void **sys_call_table = NULL; /* Global syscall table */

#ifdef CONFIG_AUDIT_MMAP
void audit_mmap_write_partial_ocasta(struct page*, struct task_struct* writer,
                                       int offset, int bytes, int from);
void* old_audit_mmap_write_partial = NULL;
void audit_mmap_read_partial_ocasta(struct page*, struct task_struct* writer,
                                      int offset, int bytes, int from);
void* old_audit_mmap_read_partial = NULL;
#endif

/* Original system calls will be stored in these variables */
static asmlinkage int (*orig_dup)(int oldfd);
static asmlinkage int (*orig_dup2)(int oldfd, int newfd);
static asmlinkage int (*orig_kill)(int pid, int sig);
static asmlinkage ssize_t (*orig_read)(int fd, void *buf, size_t count);
static asmlinkage ssize_t (*orig_write)(int fd, const void *buf, size_t count);
static asmlinkage ssize_t (*orig_pread)(int fd, void *buf, size_t count,
					loff_t offset);
static asmlinkage ssize_t (*orig_pwrite)(int fd, const void *buf, size_t count,
					 loff_t offset);
static asmlinkage ssize_t (*orig_readv)(int fd, const struct iovec * vector,
                                        unsigned long count);
static asmlinkage ssize_t (*orig_writev)(int fd, const struct iovec * vector,
                                   unsigned long count);
static asmlinkage int (*orig_fork)(struct pt_regs regs);
static asmlinkage int (*orig_vfork)(struct pt_regs regs);
static asmlinkage int (*orig_clone)(struct pt_regs regs);
static asmlinkage int (*orig_fcntl)(unsigned int fd, unsigned int cmd,
                                    unsigned long arg);
static asmlinkage int (*orig_fcntl64)(unsigned int fd, unsigned int cmd,
                                      unsigned long arg);
static asmlinkage int (*orig_close)(int fd);
static asmlinkage int (*orig_open)(const char *pathname, int flag, mode_t mode);
static asmlinkage int (*orig_creat)(const char *pathname, mode_t mode);
static asmlinkage int (*orig_execve)(struct pt_regs regs);
static asmlinkage int (*orig_exit)(int);
#ifdef AUDIT_EXIT_GROUP
static asmlinkage int (*orig_exit_group)(int);
#endif /* AUDIT_EXIT_GROUP */
static asmlinkage int (*orig_mkdir)(const char *path, mode_t mode);
static asmlinkage int (*orig_unlink)(const char *path);
static asmlinkage int (*orig_unlinkat)(int dirfd, const char *path, int flags);
static asmlinkage int (*orig_mknod)(const char *pathname, mode_t mode,
                                    dev_t dev);
static asmlinkage int (*orig_rmdir)(const char *path);
static asmlinkage int (*orig_chown)(const char *path, old_uid_t owner,
                                    old_gid_t group);
static asmlinkage int (*orig_lchown)(const char *path, old_uid_t owner,
                                     old_gid_t group);
static asmlinkage int (*orig_fchown)(unsigned int fd, old_uid_t owner,
                                     old_gid_t group);
static asmlinkage int (*orig_chown32)(const char *path, uid_t owner,
                                      gid_t group);
static asmlinkage int (*orig_lchown32)(const char *path, uid_t owner,
                                       gid_t group);
static asmlinkage int (*orig_fchown32)(unsigned int fd, uid_t owner,
                                       gid_t group);
static asmlinkage int (*orig_chmod)(const char *pathname, mode_t mode);
static asmlinkage int (*orig_fchmod)(unsigned int fd, mode_t mode);
static asmlinkage int (*orig_symlink)(const char *oldpath, const char *newpath);
static asmlinkage int (*orig_link)(const char *oldpath, const char *newpath);
static asmlinkage int (*orig_rename)(const char *oldpath, const char *newpath);
static asmlinkage int (*orig_reboot)(int magic, int magic2, int flag,
                                     void *arg);
static asmlinkage long (*orig_truncate)(const char *path, unsigned long length);
static asmlinkage int (*orig_chdir)(const char *path);
static asmlinkage int (*orig_fchdir)(int fd);
static asmlinkage int (*orig_chroot)(const char *path);
static asmlinkage int (*orig_setuid)(uid_t uid);
static asmlinkage int (*orig_setreuid)(uid_t ruid, uid_t euid);
static asmlinkage int (*orig_setresuid)(uid_t ruid, uid_t euid, uid_t suid);
static asmlinkage int (*orig_setuid32)(uid_t uid);
static asmlinkage int (*orig_setreuid32)(uid_t ruid, uid_t euid);
static asmlinkage int (*orig_setresuid32)(uid_t ruid, uid_t euid, uid_t suid);
static asmlinkage int (*orig_setgid)(gid_t gid);
static asmlinkage int (*orig_setregid)(gid_t rgid, uid_t egid);
static asmlinkage int (*orig_setresgid)(gid_t rgid, uid_t egid, uid_t sgid);
static asmlinkage int (*orig_setgid32)(gid_t gid);
static asmlinkage int (*orig_setregid32)(gid_t rgid, uid_t egid);
static asmlinkage int (*orig_setresgid32)(gid_t rgid, uid_t egid, uid_t sgid);
static asmlinkage long (*orig_truncate64)(const char *path, loff_t length);
static asmlinkage int (*orig_socketcall)(int call, unsigned long *args);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static asmlinkage unsigned long (*orig_create_module)(const char *name,
						      size_t size);
static asmlinkage unsigned long (*orig_init_module)(const char *name,
						    struct module *image);
#endif /* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static asmlinkage unsigned long (*orig_delete_module)(const char *name,
                  unsigned int flags);
#else
static asmlinkage unsigned long (*orig_delete_module)(const char *name);
#endif

static asmlinkage int (*orig_mount)(char *dev_name, char *dir_name, char *type,
                                    unsigned long flags, void *data);
static asmlinkage int (*orig_umount)(char *name, int flags);
static asmlinkage int (*orig_umount2)(char *name, int flags);
static asmlinkage ssize_t (*orig_sendfile)(int out_fd, int in_fd,
                                           off_t * offset, size_t count);
static asmlinkage int (*orig_mmap)(void *arg);
static asmlinkage int (*orig_mmap2)(unsigned long addr, unsigned long len,
				    unsigned long prot, unsigned long flags,
				    unsigned long fd, unsigned long pgoff);
static asmlinkage long (*orig_munmap)(unsigned long addr, size_t len);
static asmlinkage long (*orig_ftruncate)(unsigned int fd, unsigned long length);
static asmlinkage long (*orig_ftruncate64)(unsigned int fd, loff_t length);
static asmlinkage int (*orig_waitpid)(int pid, int * status, int options);
static asmlinkage int (*orig_wait4)(int pid, int * status, int options,
				    struct rusage *rusage);
static asmlinkage long (*orig_getcwd)(char *path, unsigned long size);
static asmlinkage long (*orig_stat)(const char *path, struct stat *buf);
static asmlinkage long (*orig_stat64)(const char *path, struct stat64 *buf);
static asmlinkage long (*orig_fstat)(unsigned int fd, struct stat *buf);
static asmlinkage long (*orig_umask)(int mask);

#ifdef VERSIONING
static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
#endif

/* System Call Replacements */
static asmlinkage int audit_fcntl(unsigned int fd, unsigned int cmd,
                                  unsigned long arg);
static asmlinkage int audit_fcntl64(unsigned int fd, unsigned int cmd,
                                    unsigned long arg);
static asmlinkage int audit_close(int fd);
static asmlinkage int audit_open(const char *, int, mode_t);
static asmlinkage int audit_creat(const char *, mode_t);
static asmlinkage int audit_execve(struct pt_regs regs);
static asmlinkage int audit_exit(int);
#ifdef AUDIT_EXIT_GROUP
static asmlinkage int audit_exit_group(int);
#endif /* AUDIT_EXIT_GROUP */
static asmlinkage int audit_mkdir(const char *path, mode_t mode);
static asmlinkage int audit_unlink(const char *path);
static asmlinkage int audit_unlinkat(int dirfd, const char *path, int flags);
static asmlinkage int audit_mknod(const char *pathname, mode_t mode, dev_t dev);
static asmlinkage int audit_rmdir(const char *path);
static asmlinkage int audit_chown(const char *path, old_uid_t owner,
                                  old_gid_t group);
static asmlinkage int audit_lchown(const char *path, old_uid_t owner,
                                   old_gid_t group);
static asmlinkage int audit_fchown(unsigned int fd, old_uid_t owner,
                                   old_gid_t group);
static asmlinkage int audit_chown32(const char *path, uid_t owner, gid_t group);
static asmlinkage int audit_lchown32(const char *path, uid_t owner,
                                     gid_t group);
static asmlinkage int audit_fchown32(unsigned int fd, uid_t owner, gid_t group);
static asmlinkage int audit_chmod(const char *pathname, mode_t mode);
static asmlinkage int audit_fchmod(unsigned int fd, mode_t mode);
static asmlinkage int audit_symlink(const char *oldpath, const char *newpath);
static asmlinkage int audit_link(const char *oldpath, const char *newpath);
static asmlinkage int audit_rename(const char *oldpath, const char *newpath);
static asmlinkage int audit_reboot(int magic, int magic2, int flag, void *arg);
static asmlinkage long audit_truncate(const char *path, unsigned long length);
static asmlinkage int audit_chdir(const char *path);
static asmlinkage int audit_fchdir(int fd);
static asmlinkage int audit_chroot(const char *path);
static asmlinkage int audit_setuid(uid_t uid);
static asmlinkage int audit_setreuid(uid_t ruid, uid_t euid);
static asmlinkage int audit_setresuid(uid_t ruid, uid_t euid, uid_t suid);
static asmlinkage int audit_setuid32(uid_t uid);
static asmlinkage int audit_setreuid32(uid_t ruid, uid_t euid);
static asmlinkage int audit_setresuid32(uid_t ruid, uid_t euid, uid_t suid);
static asmlinkage int audit_setgid(gid_t gid);
static asmlinkage int audit_setregid(gid_t rgid, gid_t egid);
static asmlinkage int audit_setresgid(gid_t rgid, gid_t egid, gid_t sgid);
static asmlinkage int audit_setgid32(gid_t gid);
static asmlinkage int audit_setregid32(gid_t rgid, gid_t egid);
static asmlinkage int audit_setresgid32(gid_t rgid, gid_t egid, gid_t sgid);
static asmlinkage long audit_truncate64(const char *path, loff_t length);
static asmlinkage int audit_socketcall(int call, unsigned long *args);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static asmlinkage unsigned long audit_create_module(const char *name,
						    size_t size);
static asmlinkage unsigned long audit_init_module(const char *name,
						  struct module *image);
#endif /* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static asmlinkage unsigned long audit_delete_module(const char *name,
                  unsigned int flags);
#else
static asmlinkage unsigned long audit_delete_module(const char *name);
#endif

static asmlinkage int audit_mount(char *dev_name, char *dir_name, char *type,
                                  unsigned long flags, void *data);
static asmlinkage int audit_umount(char *name, int flags);
static asmlinkage int audit_umount2(char *name, int flags);
static asmlinkage int audit_fork(struct pt_regs regs);
static asmlinkage int audit_vfork(struct pt_regs regs);
static asmlinkage int audit_clone(struct pt_regs regs);
static asmlinkage int audit_dup(int oldfd);
static asmlinkage int audit_dup2(int oldfd, int newfd);
static asmlinkage ssize_t audit_read(int fd, void __user *buf, size_t count);
static asmlinkage ssize_t audit_write(int fd, const void __user *buf,
                                      size_t count);
static asmlinkage ssize_t audit_pread(int fd, void __user *buf, size_t count,
				      loff_t offset);
static asmlinkage ssize_t audit_pwrite(int fd, const void __user *buf,
                                       size_t count, loff_t offset);
static asmlinkage ssize_t audit_readv(unsigned long fd,
                                      const struct iovec __user *vector,
                                      int count);
static asmlinkage ssize_t audit_writev (unsigned long fd,
                                        const struct iovec __user *vector,
                                        int count);
static asmlinkage int audit_kill(int pid, int sig);
static asmlinkage ssize_t audit_sendfile(int out_fd, int in_fd,
                                         off_t __user *offset, size_t count);
static asmlinkage int audit_mmap(void *arg);
static asmlinkage int audit_mmap2(unsigned long addr, unsigned long len,
				  unsigned long prot, unsigned long flags,
				  unsigned long fd, unsigned long pgoff);
static asmlinkage long audit_munmap(unsigned long addr, size_t len);
static asmlinkage long audit_ftruncate(unsigned int fd, unsigned long length);
static asmlinkage long audit_ftruncate64(unsigned int fd, loff_t length);
static asmlinkage int audit_waitpid(int pid, int * status, int options);
static asmlinkage int audit_wait4(int pid, int * status, int options,
				  struct rusage *rusage);
static asmlinkage long audit_getcwd(char *buf, unsigned long size);
static asmlinkage long audit_stat(const char *path, struct stat *buf);
static asmlinkage long audit_stat64(const char *path, struct stat64 *buf);
static asmlinkage long audit_fstat(unsigned int fd, struct stat *buf);
static asmlinkage long audit_umask(int mask);

#ifdef VERSIONING
static asmlinkage long audit_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long audit_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
#endif

#define _V (void *)

#ifdef JUST_EXEC
#define ONE 0
#else /* JUST_EXEC */
#define ONE 1
#endif /* JUST_EXEC */


#define ZERO 0



#ifdef SOLITUDE

/* Global syscall data */
static struct sys_call_data {
        int audit_this_call;
        int syscall_nr;
        void *audit_syscall;
        void **orig_syscall;
} sys_call_data[] = {
 {ONE, __NR_open,          audit_open,          _V&orig_open},
 {ONE, __NR_creat,         audit_creat,         _V&orig_creat},
 {ONE, __NR_execve,        audit_execve,        _V&orig_execve},
 {ONE, __NR_exit,          audit_exit,          _V&orig_exit},
#ifdef AUDIT_EXIT_GROUP
 {ONE, __NR_exit_group,    audit_exit_group,    _V&orig_exit_group},
#endif /* AUDIT_EXIT_GROUP */
 {ONE, __NR_mkdir,         audit_mkdir,         _V&orig_mkdir},
 {ONE, __NR_unlink,        audit_unlink,        _V&orig_unlink},
 {ONE, __NR_mknod,         audit_mknod,         _V&orig_mknod},
 {ONE, __NR_rmdir,         audit_rmdir,         _V&orig_rmdir},
 {ONE, __NR_chown,         audit_chown,         _V&orig_chown},
 {ONE, __NR_lchown,        audit_lchown,        _V&orig_lchown},
 {ONE, __NR_fchown,        audit_fchown,        _V&orig_fchown},
 {ONE, __NR_chown32,       audit_chown32,       _V&orig_chown32},
 {ONE, __NR_lchown32,      audit_lchown32,      _V&orig_lchown32},
 {ONE, __NR_fchown32,      audit_fchown32,      _V&orig_fchown32},
 {ONE, __NR_chmod,         audit_chmod,         _V&orig_chmod},
 {ONE, __NR_fchmod,        audit_fchmod,        _V&orig_fchmod},
 {ONE, __NR_symlink,       audit_symlink,       _V&orig_symlink},
 {ONE, __NR_link,          audit_link,          _V&orig_link},
 {ONE, __NR_rename,        audit_rename,        _V&orig_rename},
 {ZERO, __NR_reboot,        audit_reboot,        _V&orig_reboot},
 {ONE, __NR_truncate,      audit_truncate,      _V&orig_truncate},
 {ZERO, __NR_chdir,         audit_chdir,         _V&orig_chdir},
 {ZERO, __NR_fchdir,        audit_fchdir,        _V&orig_fchdir},
 {ZERO, __NR_chroot,        audit_chroot,        _V&orig_chroot},
 {ONE, __NR_setuid,        audit_setuid,        _V&orig_setuid},
 {ONE, __NR_setreuid,      audit_setreuid,      _V&orig_setreuid},
 {ONE, __NR_setresuid,     audit_setresuid,     _V&orig_setresuid},
 {ONE, __NR_setuid32,      audit_setuid32,      _V&orig_setuid32},
 {ONE, __NR_setreuid32,    audit_setreuid32,    _V&orig_setreuid32},
 {ONE, __NR_setresuid32,   audit_setresuid32,   _V&orig_setresuid32},
 {ONE, __NR_setgid,        audit_setgid,        _V&orig_setgid},
 {ONE, __NR_setregid,      audit_setregid,      _V&orig_setregid},
 {ONE, __NR_setresgid,     audit_setresgid,     _V&orig_setresgid},
 {ONE, __NR_setgid32,      audit_setgid32,      _V&orig_setgid32},
 {ONE, __NR_setregid32,    audit_setregid32,    _V&orig_setregid32},
 {ONE, __NR_setresgid32,   audit_setresgid32,   _V&orig_setresgid32},
 {ONE, __NR_truncate64,    audit_truncate64,    _V&orig_truncate64},
 {ZERO, __NR_socketcall,    audit_socketcall,    _V&orig_socketcall},
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
 {ZERO, __NR_create_module, audit_create_module, _V&orig_create_module},
#endif /* LINUX_VERSION_CODE */
 {ZERO, __NR_mount,         audit_mount,         _V&orig_mount},
 {ZERO, __NR_umount,        audit_umount,        _V&orig_umount},
 {ZERO, __NR_umount2,       audit_umount2,       _V&orig_umount2},
 {ONE, __NR_read,          audit_read,          _V&orig_read},
 {ONE, __NR_write,         audit_write,         _V&orig_write},
 {ONE, __NR_pread,         audit_pread,         _V&orig_pread},
 {ONE, __NR_pwrite,        audit_pwrite,        _V&orig_pwrite},
 {ZERO, __NR_kill,          audit_kill,          _V&orig_kill},
 {ONE, __NR_readv,         audit_readv,         _V&orig_readv},
 {ONE, __NR_writev,        audit_writev,        _V&orig_writev},
 {ZERO, __NR_dup,           audit_dup,           _V&orig_dup},
 {ZERO, __NR_dup2,          audit_dup2,          _V&orig_dup2},
 {ONE, __NR_clone,         audit_clone,         _V&orig_clone},
 {ONE, __NR_fork,          audit_fork,          _V&orig_fork},
 {ONE, __NR_vfork,         audit_vfork,         _V&orig_vfork},
 {ONE, __NR_sendfile,      audit_sendfile,      _V&orig_sendfile},
 {ZERO, __NR_close,         audit_close,         _V&orig_close},
 {ZERO, __NR_fcntl,         audit_fcntl,         _V&orig_fcntl},
 {ZERO, __NR_fcntl64,       audit_fcntl64,       _V&orig_fcntl64},
 {ZERO, __NR_mmap,          audit_mmap,          _V&orig_mmap},
 {ZERO, __NR_mmap2,         audit_mmap2,         _V&orig_mmap2},
 {ONE, __NR_ftruncate,     audit_ftruncate,     _V&orig_ftruncate},
 {ONE, __NR_ftruncate64,   audit_ftruncate64,   _V&orig_ftruncate64},
 {ONE, __NR_waitpid,       audit_waitpid,       _V&orig_waitpid},
 {ONE, __NR_wait4,         audit_wait4,         _V&orig_wait4},
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
 {ZERO, __NR_init_module,   audit_init_module,   _V&orig_init_module},
#endif /* LINUX_VERSION_CODE */
 {ZERO, __NR_delete_module, audit_delete_module, _V&orig_delete_module},
};
#else /* SOLITUDE */

/* Global syscall data */
static struct sys_call_data {
        int audit_this_call;
        int syscall_nr;
        void *audit_syscall;
        void **orig_syscall;
} sys_call_data[] = {
 {ONE, __NR_stat64,	   audit_stat64,	_V&orig_stat64},
 {ONE, __NR_stat, 	   audit_stat,	 	_V&orig_stat},
 {ONE, __NR_fstat, 	   audit_fstat,	 	_V&orig_fstat},
 {ONE, __NR_open,          audit_open,          _V&orig_open},
 {ONE, __NR_creat,         audit_creat,         _V&orig_creat},
 {ONE, __NR_execve,        audit_execve,        _V&orig_execve},
 {ONE, __NR_exit,          audit_exit,          _V&orig_exit},
#ifdef AUDIT_EXIT_GROUP
 {ONE, __NR_exit_group,    audit_exit_group,    _V&orig_exit_group},
#endif /* AUDIT_EXIT_GROUP */
 {ONE, __NR_mkdir,         audit_mkdir,         _V&orig_mkdir},
 {ONE, __NR_unlink,        audit_unlink,        _V&orig_unlink},
 {ONE, __NR_unlinkat,      audit_unlinkat,      _V&orig_unlinkat},
 {ONE, __NR_mknod,         audit_mknod,         _V&orig_mknod},
 {ONE, __NR_rmdir,         audit_rmdir,         _V&orig_rmdir},
 {ONE, __NR_chown,         audit_chown,         _V&orig_chown},
 {ONE, __NR_lchown,        audit_lchown,        _V&orig_lchown},
 {ONE, __NR_fchown,        audit_fchown,        _V&orig_fchown},
 {ONE, __NR_chown32,       audit_chown32,       _V&orig_chown32},
 {ONE, __NR_lchown32,      audit_lchown32,      _V&orig_lchown32},
 {ONE, __NR_fchown32,      audit_fchown32,      _V&orig_fchown32},
 {ONE, __NR_chmod,         audit_chmod,         _V&orig_chmod},
 {ONE, __NR_fchmod,        audit_fchmod,        _V&orig_fchmod},
 {ONE, __NR_symlink,       audit_symlink,       _V&orig_symlink},
 {ONE, __NR_link,          audit_link,          _V&orig_link},
 {ONE, __NR_rename,        audit_rename,        _V&orig_rename},
 {ZERO, __NR_reboot,        audit_reboot,        _V&orig_reboot},
 {ONE, __NR_truncate,      audit_truncate,      _V&orig_truncate},
 {ONE, __NR_chdir,         audit_chdir,         _V&orig_chdir},
 {ONE, __NR_fchdir,        audit_fchdir,        _V&orig_fchdir},
 {ONE, __NR_chroot,        audit_chroot,        _V&orig_chroot},
 {ZERO, __NR_setuid,        audit_setuid,        _V&orig_setuid},
 {ZERO, __NR_setreuid,      audit_setreuid,      _V&orig_setreuid},
 {ZERO, __NR_setresuid,     audit_setresuid,     _V&orig_setresuid},
 {ZERO, __NR_setuid32,      audit_setuid32,      _V&orig_setuid32},
 {ZERO, __NR_setreuid32,    audit_setreuid32,    _V&orig_setreuid32},
 {ZERO, __NR_setresuid32,   audit_setresuid32,   _V&orig_setresuid32},
 {ZERO, __NR_setgid,        audit_setgid,        _V&orig_setgid},
 {ZERO, __NR_setregid,      audit_setregid,      _V&orig_setregid},
 {ZERO, __NR_setresgid,     audit_setresgid,     _V&orig_setresgid},
 {ZERO, __NR_setgid32,      audit_setgid32,      _V&orig_setgid32},
 {ZERO, __NR_setregid32,    audit_setregid32,    _V&orig_setregid32},
 {ZERO, __NR_setresgid32,   audit_setresgid32,   _V&orig_setresgid32},
 {ONE, __NR_truncate64,    audit_truncate64,    _V&orig_truncate64},
 {ZERO, __NR_socketcall,    audit_socketcall,    _V&orig_socketcall},
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
 {ZERO, __NR_create_module, audit_create_module, _V&orig_create_module},
#endif /* LINUX_VERSION_CODE */
 {ONE, __NR_mount,         audit_mount,         _V&orig_mount},
 {ONE, __NR_umount,        audit_umount,        _V&orig_umount},
 {ONE, __NR_umount2,       audit_umount2,       _V&orig_umount2},
 {ONE, __NR_read,          audit_read,          _V&orig_read},
 {ONE, __NR_write,         audit_write,         _V&orig_write},
 {ONE, __NR_pread,         audit_pread,         _V&orig_pread},
 {ONE, __NR_pwrite,        audit_pwrite,        _V&orig_pwrite},
 {ONE, __NR_kill,          audit_kill,          _V&orig_kill},
 {ONE, __NR_readv,         audit_readv,         _V&orig_readv},
 {ONE, __NR_writev,        audit_writev,        _V&orig_writev},
 {ONE, __NR_dup,           audit_dup,           _V&orig_dup},
 {ONE, __NR_dup2,          audit_dup2,          _V&orig_dup2},
 {ONE, __NR_clone,         audit_clone,         _V&orig_clone},
 {ONE, __NR_fork,          audit_fork,          _V&orig_fork},
 {ONE, __NR_vfork,         audit_vfork,         _V&orig_vfork},
 {ONE, __NR_sendfile,      audit_sendfile,      _V&orig_sendfile},
 {ONE, __NR_close,         audit_close,         _V&orig_close},
 {ZERO, __NR_fcntl,         audit_fcntl,         _V&orig_fcntl},
 {ZERO, __NR_fcntl64,       audit_fcntl64,       _V&orig_fcntl64},
 {ONE, __NR_mmap,          audit_mmap,          _V&orig_mmap},
 {ONE, __NR_mmap2,         audit_mmap2,         _V&orig_mmap2},
 {ONE, __NR_munmap,         audit_munmap,         _V&orig_munmap},
 {ONE, __NR_ftruncate,     audit_ftruncate,     _V&orig_ftruncate},
 {ONE, __NR_ftruncate64,   audit_ftruncate64,   _V&orig_ftruncate64},
 {ZERO, __NR_waitpid,       audit_waitpid,       _V&orig_waitpid},
 {ONE, __NR_wait4,         audit_wait4,         _V&orig_wait4},
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
 {ZERO, __NR_init_module,   audit_init_module,   _V&orig_init_module},
#endif /* LINUX_VERSION_CODE */
 {ZERO, __NR_delete_module, audit_delete_module, _V&orig_delete_module},
 {ONE, __NR_getcwd, 	   audit_getcwd, 	_V&orig_getcwd},
 {ONE, __NR_umask, 	   audit_umask,	 	_V&orig_umask},
#ifdef VERSIONING
 {ONE, __NR_getdents64,	   audit_getdents64, 	_V&orig_getdents64,},
 {ONE, __NR_getdents,	   audit_getdents, 	_V&orig_getdents,},
#endif
};

#endif /* SOLITUDE */

#undef _V


static const int MAXAUDIT = sizeof(sys_call_data)/sizeof(struct sys_call_data);
static const int MAXAUDIT_ON = sizeof(sys_call_data)/sizeof(struct sys_call_data);

static DECLARE_MUTEX(audit_lock); /* Global auditing lock */
static DECLARE_WAIT_QUEUE_HEAD(audit_queue); /* queue of waiting writers */
static DECLARE_WAIT_QUEUE_HEAD(sender_queue); /* a single reader */
static DECLARE_MUTEX(save_file_lock);
static DECLARE_MUTEX(log_stat_lock);

/* Section 1 */
static int auditmodule_ioctl(struct inode *, struct file *, unsigned int,
                             unsigned long);
static int audit_start(unsigned long arg);
#ifndef VERSIONING
static int audit_set_output_file(unsigned long arg);
static int audit_set_data_file(unsigned long arg);
static int audit_set_data_file_name(char *arg);
#endif
static int audit_set_work_dir(char *arg);
static void audit_stop(void);

/* Section 2 */
static void audit_free_pgnode(struct pgnode *);
static void audit_free_pages(struct list_head *head, int *nr);
static void audit_wait_active_pages(void);

/* Section 4 */
static void audit_move_to_ready_list(void);
static inline int audit_move_to_sending_list(void);
static void audit_move_to_free_list(void);
static int audit_sendpage(struct file *file, struct page *page);
static int audit_thread(void *);

/* Section 5 */
static int audit_info_open(struct inode *, struct file *);
static int audit_info_close(struct inode *, struct file *);
static ssize_t audit_info_read(struct file *, char *, size_t, loff_t *);
static int snapshot_ioctl(struct inode * inode, struct file * filp, 
                          unsigned int cmd, unsigned long user_data);

#ifdef SOLITUDE
static int solitude_ioctl(struct inode * inode, struct file * filp, 
                          unsigned int cmd, unsigned long user_data);
static int solitude_commit(unsigned long user_data);
#endif /* SOLITUDE */

/* Section 6 */
static void audit_on(void);
static void audit_off(void);
static int audit_switch(void);
static void audit_register_oom(void);
static void audit_unregister_oom(void);

static inline int get_inode_path(const char *pathname,
               struct custat *iself, struct custat *iparent,
               char **canonpath, unsigned int canonpathlen);
static unsigned long *locate_sys_call_table(void);
#ifdef GET_SYMBOL
static int __init get_symbol(char *symbol, void **addr);
#endif
static inline int get_process_start_time(pid_t pid);
#ifdef SAVE_FILE_DATA
static int save_file(const char *srcpath);
#endif

#ifdef SOLITUDE
static int do_snapshot_sendfile(snapshot_class* sc);
#endif /* SOLITUDE */

// Kernel 2.4 and above only
static struct file_operations file_ops = {
        ioctl: auditmodule_ioctl,
};

static struct file_operations info_ops = {
        read:    audit_info_read,
        open:    audit_info_open,
        release: audit_info_close,
};

static struct file_operations snapshot_ops = {
        ioctl: snapshot_ioctl,
};

#ifdef SOLITUDE
static struct file_operations solitude_ops = {
        ioctl: solitude_ioctl,
};
#endif /* SOLITUDE */

/* Section 7 */
#define EVENT_SIZE(class) class event; int event_size = sizeof(event)
#define PATH_SIZE event.filename_len = strnlen_user(pathname, MAX_PATH)
#define SRC_PATH_SIZE event.source_filename_len = \
        strnlen_user(srcpath, MAX_PATH)
#define CANON_PATH_SIZE event.filename_len = strnlen(canonpath, MAX_PATH) + 1
#define FULLPATH_SIZE event.filename_len = strnlen(fullpath, MAX_PATH) + 1
#define SRC_CANON_PATH_SIZE event.source_filename_len = \
                            strnlen(srccanonpath, MAX_PATH) + 1
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#define PWD_SIZE char __pwd_buf[MAX_PATH]; char *pwd_buf; \
                 pwd_buf = d_path(&(current->fs->pwd), \
                 __pwd_buf, MAX_PATH); event.pwd_len = strlen(pwd_buf) + 1
#else
#define PWD_SIZE char __pwd_buf[MAX_PATH]; char *pwd_buf; \
                 pwd_buf = d_path(current->fs->pwd, current->fs->rootmnt, \
                 __pwd_buf, MAX_PATH); event.pwd_len = strlen(pwd_buf) + 1
#endif
#define MODNAME_SIZE event.name_len = strnlen_user(name, MAX_PATH)

#define AUDIT_GENERIC_WOTIME(nr_blocks, datalen) \
        e.size = audit_generic_wotime((header_token *)&event, event_size, \
				       nr_blocks, datalen)
#define AUDIT_GENERIC(nr_blocks, datalen) \
        e.size = audit_generic((header_token *)&event, event_size, nr_blocks, \
                               datalen)
#define AUDIT_ALLOC if (!audit_event_alloc(&e)) { goto bail; }
#define WRITE_EVENT audit_write_event(&event, event_size, &e)
#define PAGE_ALIGN_ALLOC if (!audit_event_alloc_page_aligned(e)) \
        { printas("PAGE ALIGN ALLOC FAILED\n"); goto bail; }

#define WRITE_PATH audit_write_user_event(pathname, event.filename_len, &e)
#define WRITE_SRC_PATH audit_write_user_event(srcpath, \
                                              event.source_filename_len, &e)
#define WRITE_CANON_PATH audit_write_event(canonpath, event.filename_len, &e)
#define WRITE_FULLPATH audit_write_event(fullpath, event.filename_len, &e)
#define WRITE_SRC_CANON_PATH audit_write_event(srccanonpath, \
                                               event.source_filename_len, &e)
#define WRITE_PWD audit_write_event(pwd_buf, event.pwd_len, &e)
#define WRITE_USER_DATA if (event.data_len > 0) { \
        audit_write_user_event(buf, event.data_len, &e); }
#define WRITE_MODNAME audit_write_user_event(name, event.name_len, &e)
#define SEND_DATA ASSERT_AUDIT(e.size == 0); \
                  if (atomic_dec_and_test(&(e.node)->count) && \
                      e.try_sending_pages) \
                        audit_try_sending_pages();

#define DECLARE_INODE(i) struct custat i
#define SET_INODE_NR_SETSB(inr, d, i, g, m, s) SET_INODE_NR(inr, d, i, g, m);

/* Section 8 */
#ifdef SOLITUDE
static int process_tainted_by_file_f(struct file* f);
static int process_tainted_by_file_nd(struct nameidata nd);
static int file_tainted_by_process_f(struct file* file, struct inode_nr* inr, 
                                     char send_orig);
static int file_tainted_by_process_nd(const char* path, struct inode_nr* inr, 
                                      char send_orig);
static int check_if_in_ifs(struct file* f, const char* path);
#endif /* SOLITUDE */
static void get_task_comm_copy(char *buf, struct task_struct *tsk);

/* Section 9 */
#ifdef SOLITUDE
static int ifs_start(struct ifs_capability_set __user *ucap_set);
static int ifs_fork(int child_pid);
static void ifs_execve(void);
#endif /* SOLITUDE */

/* Section 10 */
// versioning file system
int isdigit(char ch)
{
   return ch >= '0' && ch <='9';
}

int atoi(char *buf)
{
   int i = 0;
   
   while (isdigit(*buf))
	i = i * 10 + (*(buf ++)) - '0';
   return i;
}

time_t time(void);

time_t time()
{
   struct timeval tv;
   do_gettimeofday(&tv);
   return tv.tv_sec;
}

/*
 * get the full path
 * 	fullpath, path are all in kernel space
 */
char *get_fullpath(char *fullpath, const char *path, int fullpath_size)
{
	mm_segment_t fs;
	char currentpath[MAX_PATH];
	long ret;

	if (*path != '/' && orig_getcwd) {
		fs = get_fs();
		set_fs(get_ds());
		ret = orig_getcwd(currentpath, sizeof(currentpath));
		set_fs(fs);
		if (ret > 0 && (strlen(currentpath) + strlen(path) + 1 < fullpath_size)) {
			strcpy(fullpath, currentpath);
			strcat(fullpath, "/");
			strcat(fullpath, path);
		} else {
			strncpy(fullpath, path, fullpath_size);
			printk("orig_getcwd failed %ld\n", ret);
		}
	} else
		strncpy(fullpath, path, fullpath_size);
	return fullpath;
}

/*
 * get the full path
 *      fullpath is in kernel space
 *	path is in user space
 */
char *get_fullpath_usr(char *fullpath, const char *path, int fullpath_size)
{
	mm_segment_t fs;
	char currentpath[MAX_PATH];
	long ret;

	if (copy_from_user(fullpath, path, strnlen_user(path, fullpath_size))) {
		printk("%s:copy_from_user failed\n", __FUNCTION__);
		goto bail;
	}
	if (*fullpath != '/' && orig_getcwd) {
		fs = get_fs();
		set_fs(get_ds());
		ret = orig_getcwd(currentpath, sizeof(currentpath));
		set_fs(fs);
		if (ret > 0 && (strlen(currentpath) + strlen(fullpath) + 1 < fullpath_size)) {
			memmove(fullpath + strlen(currentpath) + 1, fullpath, strlen(fullpath) + 1);
			memcpy(fullpath, currentpath, strlen(currentpath));
			fullpath[strlen(currentpath)] = '/';
		} else {
			printk("orig_getcwd failed\n");
		}
	}
bail:
	return fullpath;
}

/*
 * check if a path point to a regular file
 * path is a kernel space string
 * caller should set fs properly
 * returns 1 and set file_size when file is a regular file
 *         0 when file is not a regular file or file does not exist
 */
int is_regfile(const char *path, size_t *file_size)
{
	umode_t i_mode;
	int ret = 0;
	struct stat stbuf;

	if (!orig_stat(path, &stbuf)) {
		i_mode = stbuf.st_mode;
		ret = S_ISREG(i_mode) && !S_ISDIR(i_mode) && !S_ISCHR(i_mode) && !S_ISBLK(i_mode) && !S_ISFIFO(i_mode) && !S_ISSOCK(i_mode);
		if (ret) {
			*file_size = stbuf.st_size;
		}
	} //else
	//	printk("%s: %s not exist\n", __FUNCTION__, path);
	return ret;
} 

/*
 * check if a path point to a directory
 * path is a kernel space string
 * returns 1 and set file_size
 */
int is_directory(const char *path, size_t *file_size)
{
	umode_t i_mode;
	int ret = 0;
	struct stat stbuf;

	if (!orig_stat(path, &stbuf)) {
		i_mode = stbuf.st_mode;
		ret = S_ISDIR(i_mode) && !S_ISCHR(i_mode) && !S_ISBLK(i_mode) && !S_ISFIFO(i_mode) && !S_ISSOCK(i_mode);
		if (ret)
			*file_size = stbuf.st_size;
	} else
		printk("%s: %s not exist\n", __FUNCTION__, path);
	return ret;
} 

#define STR_COMMA 	", "
#define STR_COLON 	":"
#define STR_LINEFEED   	"\n"

#ifdef VERSIONING

static DECLARE_MUTEX(node_lock); /* Global node lock */
static DECLARE_MUTEX(autoconf_lock); /* Global autoconf lock */
static DECLARE_MUTEX(version_lock); /* Global version lock */

//static char* redirectpath = "/";
//static char* deletedmodifier = ".  versionfs! deleted";
//static char* versionmodifier = VERSIONMODIFIER;
static char* specialversion = ".! version";
static char* revertpath = "/tmp/";

int malloced_redir = 0, malloced_ver = 0, malloced_deleted = 0;
int revert_version(const char *path, const char *revertpath, int version);
int update_version(const char* path, size_t size, off_t offset, char truncate, const char *type);
int update_version_from_snapshot(const char* path, const char *snapshot_path);

static int writebuffer(int file, const char* buffer, int len)
{
    int ret = 0;

    //printk("%s: %p(%d)\n", __FUNCTION__, buffer, len);
    while (len > 0) {
	ret = orig_write(file, buffer, len);
	if (ret <= 0) {
    		printk("%s: failed for %p (%d) -> %d\n", __FUNCTION__, buffer, len, ret);
		goto out;
	}
	len -= ret;
	buffer += ret;
    }
out:
    return ret;
}

static int readbuffer(int file, char *buffer, int len, int offset)
{
    int ret = 0;

    //printk("%s: %p(%d)\n", __FUNCTION__, buffer, len);
    while (len > 0) {
	ret = orig_pread(file, buffer, len, offset);
	if (ret < 0) {
    		printk("%s: failed %d\n", __FUNCTION__, ret);
		goto out;
	} else if (ret == 0)
		goto out;
	len -= ret;
	buffer += ret;
    }
out:
    return ret;
}

/*
 * log statistical information
 * Note: fs should be set properly before calling this function
 */ 
#define STAT_FILE_NAME "stat.log"

/*
 * log event to stat log file
 * returns 0 on success, 1 on failure
 */
int log_stat(const char *path, time_t timestamp, off_t offset, size_t size, const char *type)
{
	int fd, ret = 0;
	char buf[TASK_COMM_LEN], logname[MAX_PATH];

	down(&log_stat_lock);
	snprintf(logname, sizeof(logname), "%s/%s", auditdata.work_dir, STAT_FILE_NAME);
	// do not log activity on log file, since it can causes the calling application that read the log file to do the reading forever
	if (strcmp(path, logname) == 0)
		goto bail;
	fd = orig_open(logname, O_WRONLY|O_CREAT|O_APPEND|O_NONBLOCK, 0777);
	if (fd >= 0) {
        	get_task_comm_copy(buf, current);
		orig_write(fd, buf, strlen(buf));
		orig_write(fd, STR_COMMA, strlen(STR_COMMA));
		orig_write(fd, type, strlen(type));
		orig_write(fd, STR_COMMA, strlen(STR_COMMA));
		orig_write(fd, path, strlen(path));
		orig_write(fd, STR_COMMA, strlen(STR_COMMA));
		sprintf(buf, "%d", (int)offset);
		orig_write(fd, buf, strlen(buf));
		orig_write(fd, STR_COMMA, strlen(STR_COMMA));
		sprintf(buf, "%d", (int)size);
		orig_write(fd, buf, strlen(buf));
		orig_write(fd, STR_COMMA, strlen(STR_COMMA));
		sprintf(buf, "%d", (int)timestamp);
		orig_write(fd, buf, strlen(buf));
		orig_write(fd, STR_LINEFEED, strlen(STR_LINEFEED));
		orig_close(fd);
		ret = 0;
	} else {
		ret = 1;
		printk("%s: Unable to open %s (%d)\n", __FUNCTION__, logname, fd);
	}
bail:
	up(&log_stat_lock);
	return ret;
}

/*
 * update version log for a file
 * path, frompath, and type are kernel address space strings
 * full file size is indicated when size is -1 and offset is zero
 * returns 0 on success
 */
#define BUF_SIZE 512

int update_version_ex(const char* path, const char *frompath, size_t size, off_t offset, char truncate, const char *type)
{
    int originalfile; // file handle
    int versionfile;  // file handle
    char *buffer = NULL;
    char verpath[MAX_PATH];
    int ret = -1;
    time_t timestamp = 0;
    char extendseof = 0;
    size_t tempsize = size;
    off_t tempoffset = offset;
    struct version_info header;
    mm_segment_t fs;
    size_t file_size;

    //printk("%s (%s) offset:%ld size:%d\n", __FUNCTION__, path, offset, size); 
    down(&version_lock);
    fs = get_fs();
    set_fs(get_ds());
    if (!is_regfile(path, &file_size))
	goto out1;
    if (offset == 0 && size == -1)
	size = file_size;

    timestamp = time();
    log_stat(path, timestamp, offset, size, type);

    strcpy(verpath, path);
    strcat(verpath, VERSIONMODIFIER);

    if ((buffer = kmalloc(BUF_SIZE, GFP_KERNEL)) == NULL) {
	printk("%s: buffer allocation failed\n", __FUNCTION__);
	goto out1;
    }
    originalfile = orig_open(frompath, O_RDONLY, 0400);
    if (originalfile < 0) {
	printk("%s:open %s failed %d\n", __FUNCTION__, frompath, originalfile);
	goto out1;
    }
    versionfile = orig_open(verpath, O_WRONLY|O_APPEND, 0600);
    if (versionfile < 0)
	versionfile = orig_open(verpath, O_CREAT|O_WRONLY, 0600);
    
    if (versionfile < 0) {
    	printk("%s:open %s failed %d\n", __FUNCTION__, verpath, versionfile);
    	orig_close(originalfile);
    	goto out1;
    }
    
    if (truncate)
	tempsize = BUF_SIZE;
    while (tempsize > 0) {
	ret = readbuffer(originalfile, buffer, (tempsize > BUF_SIZE) ? BUF_SIZE : tempsize, tempoffset);
	if (ret < 0) {
		printk("%s:readbuffer failed for %s\n", __FUNCTION__, path);
		goto out;
	}
	if (!truncate) tempsize -= ret;
	tempoffset += ret;
	if (ret == 0) {
	    extendseof = 1;
	    size = tempoffset - offset;
	    tempsize = 0;
	}
    }
    
    header.timestamp = timestamp;
    header.offset = offset;
    header.size = size;
    header.extendseof = extendseof;
    if (writebuffer(versionfile, (char *)&header, sizeof(header)) <= 0) {
	printk("%s:writebuffer failed for %s\n", __FUNCTION__, verpath);
	goto out;
    }
    
    while (size > 0) {
        ret = readbuffer(originalfile, buffer, (size > BUF_SIZE) ? BUF_SIZE : size, offset);
	if (ret < 0) {
		printk("%s:readbuffer failed for %s\n", __FUNCTION__, path);
		goto out;
	}
	if (writebuffer(versionfile, buffer, ret) <= 0) {
		printk("%s:writebuffer failed for %s\n", __FUNCTION__, verpath);
		goto out;
	}
	size -= ret;
	offset += ret;
    }
    ret = 0;
out:
    orig_close(versionfile);
    orig_close(originalfile);
out1:
    if (buffer != NULL)
    	kfree(buffer);
    set_fs(fs);
    up(&version_lock);
    return ret;
}

int update_version(const char* path, size_t size, off_t offset, char truncate, const char *type)
{
    return update_version_ex(path, path, size, offset, truncate, type);
}

int update_version_from_snapshot(const char* path, const char *snapshot_path)
{
    return update_version_ex(path, snapshot_path, -1, 0, 1, "SV");
}

void get_filename_from_path(const char *fullpath, char *filename, int filename_len)
{
    char *sep = strrchr(fullpath, '/');
    if (sep != NULL)
	strncpy(filename, sep + 1, filename_len);
    else
	strncpy(filename, fullpath, filename_len);
    filename[filename_len - 1] = '\0';
}

/*
 * parameters:
 *		path		kernel space input
 *		fullpath	kernel space output
 */
int parse_versioning_path(const char *path, char *fullpath)
{
    char verbuf[10];
    int version;
    char revertfullpath[MAX_PATH];
    char filename[MAX_PATH];
    int res = 0;
	
    printk("parse_versioning_path %s\n", path);
    /* check for special version file */
    if (strlen(path) >= strlen(specialversion) &&
	!strcmp(specialversion, 
		&(path[strlen(path) - strlen(specialversion)]))) {
	strncpy(verbuf, &(path[strlen(path) - strlen(specialversion) - 3]), 3);

	version = atoi(verbuf);
	strncpy(fullpath, path, strlen(path) - strlen(specialversion) - 4);
	fullpath[strlen(path) - strlen(specialversion) - 4] = '\0';
	get_filename_from_path(path, filename, sizeof(filename));
	sprintf(revertfullpath, "%s%s", revertpath, filename);
	printk("get_file_full_path: extract special version %d of %s into %s\n", version, fullpath, revertfullpath);
	if (revert_version(fullpath, revertfullpath, version)) {
		strcpy(fullpath, revertfullpath);
		res = 1;
	}
	else
		strcpy(fullpath, path);
    } else
	strcpy(fullpath, path);
    return res;
}

/*
 * Note that this routine will allocate memory for data and the caller is 
 * responsible to deallocate the memory
 * return code: 1	file undo data in pdata
 *		2	file was truncated to zero length
 *		0	failed
 */
int find_versioninfo(const char *versionpath, int version, struct version_info *ver_inf, char **pdata)
{
    int fd;
    int ver = 0;
    int ret = 0;
    int offset = 0;

    if (version <= 0)
	return 0;
    fd = orig_open(versionpath, O_RDONLY, 0400);
    if (fd <= 0)
	return 0;
    for (ver = 0; ver < version; ver++) {
	if (readbuffer(fd, (char *)ver_inf, sizeof(struct version_info), offset) != sizeof(struct version_info))
		break;
	offset += sizeof(struct version_info);
    	if (ver == version - 1) {
    		if (ver_inf->size > 0) {
			*pdata = (char *)kmalloc(ver_inf->size, GFP_KERNEL);
			if (*pdata != NULL && (readbuffer(fd, *pdata, ver_inf->size, offset) == ver_inf->size)) {
				//printk("find_versioninfo: (%s) version info (%d) #%d-->offset:%ld, size:%d, extendseof:%d\n", versionpath, sizeof(struct version_info), ver, ver_inf->offset, ver_inf->size, ver_inf->extendseof);
				offset += ver_inf->size;
				ret = 1;
			} else
				break;
    		} else if (ver_inf->size == 0 && ver_inf->extendseof)
			ret = 2;
		break;
    	} else {
		if (ver_inf->size > 0)
			offset += ver_inf->size;
	}
    }
    orig_close(fd);
    return ret;
}

#define COPY_FILE_BUF_SIZE 512

/*
 * copy content of a file
 * returns 1 when succeeded
 */
int copy_file(const char *srcpath, const char *destpath)
{
    int srcfd, destfd, size;
    char buf[COPY_FILE_BUF_SIZE];
    int ret = 1;
  
    printk("%s: %s to %s\n", __FUNCTION__,srcpath, destpath);
    srcfd = orig_open(srcpath, O_RDONLY, 0400);
    if (srcfd == -1) {
	ret = 0;
	goto bail;
    }
    destfd = orig_open(destpath, O_WRONLY|O_CREAT, 0600);
    if (destfd == -1) {
	printk("%s: unable to create %s\n", __FUNCTION__, destpath);
	orig_close(srcfd);
	ret = 0;
	goto bail;
    }
    while (1) {
	size =  orig_read(srcfd, buf, COPY_FILE_BUF_SIZE);
	if (size > 0) {
		if (orig_write(destfd, buf, size) == -1) {
			printk("%s: write %d bytes failed\n", __FUNCTION__, size);
			ret = 0;
			break;
		}
	}
	else 
		break;
	if (size != COPY_FILE_BUF_SIZE)
		break;
    }
    orig_close(srcfd);
    orig_close(destfd);
bail:
    printk("%s: %s to %s returns %d\n", __FUNCTION__,srcpath, destpath, ret);
    return ret;
}

/*
 * performs byte-to-byte comparsion of two files
 * srcpath and destpath are kernel space strings
 * returns 1 when files have exactly the same content and same length
 *	   0 when files have different contens (or error occurs)
 */
#define COMPARE_FILE_BUF_SIZE 512

int compare_file(const char *srcpath, const char *destpath)
{
    int srcfd, destfd, size, ret = 0;
    char *buf, *srcbuf, *destbuf;
    size_t srcsize, destsize;
    mm_segment_t old_fs;
  
    printk("%s: %s to %s\n", __FUNCTION__,srcpath, destpath);
    old_fs = get_fs();
    set_fs(get_ds());
    if (!is_regfile(srcpath, &srcsize)) {
	printk("%s: %s is not a regular file\n", __FUNCTION__, srcpath);
	goto out;
    } 
    if (!is_regfile(destpath, &destsize)) {
	printk("%s: %s is not a regular file\n", __FUNCTION__, destpath);
	goto out;
    }
    //printk("%s: %s is %d, %s is %d\n", __FUNCTION__, srcpath, (int)srcsize, destpath, (int)destsize);
    if (srcsize != destsize) {
	printk("%s: %s and %s differs in size (%d vs %d)\n", __FUNCTION__, srcpath, destpath, srcsize, destsize);
	goto out;
    }
    if ((buf = kmalloc(COMPARE_FILE_BUF_SIZE * 2, GFP_KERNEL)) == NULL) {
	printk("%s: allocate buffer failed\n", __FUNCTION__);
	goto out;
    }
    srcbuf = buf;
    destbuf = buf + COMPARE_FILE_BUF_SIZE;
    srcfd = orig_open(srcpath, O_RDONLY, 0400);
    if (srcfd == -1) {
	printk("%s: unable to open %s\n", __FUNCTION__, srcpath);
	kfree(buf);
	goto out;
    }
    destfd = orig_open(destpath, O_RDONLY, 0400);
    if (destfd == -1) {
	printk("%s: unable to open %s\n", __FUNCTION__, destpath);
	orig_close(srcfd);
	kfree(buf);
	goto out;
    }
    //printk("%s: compare content of %s and %s\n", __FUNCTION__, srcpath, destpath);
    while (1) {
	size =  orig_read(srcfd, srcbuf, COMPARE_FILE_BUF_SIZE);
	if (size > 0) {
		if (orig_read(destfd, destbuf, size) != size) {
			//printk("%s: %s is shorter\n", __FUNCTION__, destpath);
			break;
		}
		if (memcmp(srcbuf, destbuf, size)) {
			//printk("%s: %s and %s differs in content\n", __FUNCTION__, srcpath, destpath);
			break;
		}
	} else {
		// compare succeded until the end of file
		if (size == 0) {
			if (orig_read(destfd, destbuf, COMPARE_FILE_BUF_SIZE) == 0)
				ret = 1;
			//else
			//	printk("%s: %s and %s differs in size when reading them\n", __FUNCTION__, srcpath, destpath);
		} else
			printk("%s: read %s failed %d\n", __FUNCTION__, srcpath, size);
		break;
	}
    }
    orig_close(srcfd);
    orig_close(destfd);
    kfree(buf);
out:
    set_fs(old_fs);
    return ret;
}

int revert_version(const char *path, const char *revertpath, int version)
{
    struct version_info ver_inf;
    int fd, ret = 0;
    char *data = NULL;
    char verpath[MAX_PATH];
    mm_segment_t fs;
    int found_version = 0;

    fs = get_fs();
    set_fs(get_ds());

    strcpy(verpath, path);
    strcat(verpath, VERSIONMODIFIER);

    found_version = find_versioninfo(verpath, version, &ver_inf, &data);
    if (found_version) {
    	if (copy_file(path, revertpath)) {
		fd = orig_open(revertpath, O_WRONLY, 0400);
		if (fd > 0) {
			if (found_version == 1) {
				if (orig_pwrite(fd, data, ver_inf.size, ver_inf.offset) == ver_inf.size) {
					if (ver_inf.extendseof) {
						//printk("%s: trunate %s at %ld\n", __FUNCTION__, revertpath, ver_inf.offset + ver_inf.size);
						orig_ftruncate(fd, ver_inf.offset + ver_inf.size);
					}
					ret = 1;
				} else
					printk("%s: write %s failed\n", __FUNCTION__, revertpath);
			} else if (found_version == 2) {
				orig_ftruncate(fd, 0);
				ret = 1;
			}
			orig_close(fd);
		} else
			printk("%s: open %s for write failed %d\n", __FUNCTION__, revertpath, fd);
		kfree(data);
	} else
		printk("%s: copy_file %s -> %s faild\n", __FUNCTION__, path, revertpath);
    } else
	printk("%s: unable to find version #%d for %s\n", __FUNCTION__, version, path);

    set_fs(fs);
    return ret;
}

#define MAX_NODE_NUM 1000

struct node {
    unsigned short dev;
    unsigned long ino;
    unsigned int igen;
    char filename[MAX_PATH];
    int ref_times;
#ifdef VERSIONING_SNAPSHOT
    u32 vsnapshot;
#endif
};

struct node node_table[MAX_NODE_NUM];
static int node_count = 0;

int update_version(const char* path, size_t size, off_t offset, char truncate, const char *type);
int parse_versioning_path(const char *path, char *fullpath);

static struct node *lookup_node(unsigned short dev, unsigned long ino, unsigned int igen)
{
   struct node *node;
   int index;
 
   for (index = 0; index < MAX_NODE_NUM; index++) {
	node = &node_table[index];
	if (node->dev == dev && node->ino == ino && node->igen == igen) {
		node->ref_times ++;
		return node;
	}
   }
   return NULL;
}

/*
 * retrieve filename by dev, ino, and igen
 * return 0 on success
 */
#ifdef VERSIONING_SNAPSHOT
static int get_name_from_node(unsigned short dev, unsigned long ino, unsigned int igen, char *filename, int filename_len, u32 *vsnapshot)
#else
static int get_name_from_node(unsigned short dev, unsigned long ino, unsigned int igen, char *filename, int filename_len)
#endif /* VERSIONING_SNAPSHOT */
{
   struct node *node = NULL;
   int res = 1;
   down(&node_lock);
   node = lookup_node(dev, ino, igen);
   if (node != NULL) {
	strncpy(filename, node->filename, filename_len);
	filename[filename_len - 1] = '\0';
#ifdef VERSIONING_SNAPSHOT
	if (vsnapshot)
		*vsnapshot = node->vsnapshot;
#endif /* VERSIONING_SNAPSHOT */
	res = 0;
   }
   up(&node_lock);
   return res;
}

static void remove_node(unsigned short dev, unsigned long ino, unsigned int igen)
{
   struct node *node = NULL;
   down(&node_lock);
   node = lookup_node(dev, ino, igen);
   if (node != NULL) {
	memset(node, 0, sizeof(struct node));
	node_count --;
   } /* else {
	printk("$s: pid(%d) cannot find (%d, %ld, %d)\n", __FUNCTION__, current->pid, dev, ino, igen);
   } */
   up(&node_lock);
}

#ifdef VERSIONING_SNAPSHOT
static int add_node(unsigned short dev, unsigned long ino, unsigned int igen, const char *filename, u32 vsnapshot)
#else
static int add_node(unsigned short dev, unsigned long ino, unsigned int igen, const char *filename)
#endif /* VERSIONING_SNAPSHOT */
{
   int index;
   int min_reftimes = 65536;
   int min_reftimes_index = 0;
   int avl_index = 0;

   down(&node_lock);
   if (node_count == MAX_NODE_NUM) {
	for (index = 0; index < MAX_NODE_NUM; index++) {
		if (node_table[index].ref_times < min_reftimes) {
			min_reftimes = node_table[index].ref_times;
			min_reftimes_index = index;
		}
	}
	node_table[min_reftimes_index].dev = 0;
	node_table[min_reftimes_index].ino = 0;
	node_table[min_reftimes_index].igen = 0;
	node_table[min_reftimes_index].filename[0] = '\0';
	node_count --;
	printk("%s: evicted entry reftimes(%d) at %d\n", __FUNCTION__, min_reftimes, min_reftimes_index);
	avl_index = min_reftimes_index;
   } else {
   	for (index = 0; index < MAX_NODE_NUM; index++) {
		if (node_table[index].dev == 0 && node_table[index].ino == 0 && node_table[index].igen == 0) {
			avl_index = index;
			break;
		}
   	}
   }
   node_table[avl_index].dev = dev;
   node_table[avl_index].ino = ino;
   node_table[avl_index].igen = igen;
   node_table[avl_index].ref_times = 0;
#ifdef VERSIONING_SNAPSHOT
   node_table[avl_index].vsnapshot = vsnapshot;
#endif /* VERSIONING_SNAPSHOT */
   strcpy(node_table[avl_index].filename, filename);
   node_count ++;
   //printk("%s(%d): (%d, %ld, %d) -> %s, node_count is %d\n", __FUNCTION__, current->pid, dev, ino, igen, filename, node_count);
   up(&node_lock);
   return 1;
}
#endif

#ifdef ACCESS_REDIRECT

#define AUTOCONF_FILENAME	"/etc/ocasta/autoconf.conf"
#define MAX_AUTOCONF_NUM	5

struct autoconf {
	char proc_name[TASK_COMM_LEN];
	char file_name[MAX_PATH];
	int version;
};

static struct autoconf autoconf_table[MAX_AUTOCONF_NUM];
static int autoconf_count = 0;

int load_autoconf(void);

int load_autoconf()
{
    mm_segment_t fs;
    int fd;
    char buf[80];
    off_t offset = 0;
    int index = 0;
    int line = 0;
    int ret, i;

    printk("load autoconf\n");
    down(&autoconf_lock);    
    if (orig_open && orig_pread && orig_close) {
	fs = get_fs();
	set_fs(get_ds());

	fd = orig_open(AUTOCONF_FILENAME, O_RDONLY, 0400);
	if (fd > 0) {
		while (1) {
			char *sep = NULL;
			
			ret = orig_pread(fd, buf, sizeof(buf), offset);

			if (ret <= 0)
				break;
			sep = strchr(buf, '\n');
			if (sep != NULL) {
				ret = sep - buf + 1;
			}
			buf[ret] = '\0';
			
			offset += ret;
			if (buf[0] != '#') {
				char *filename = NULL;
				char *version = NULL;

				char *ch = buf;
				while (*ch != ' ' && *ch != '\t' && *ch != '\0')
					ch ++;
				strncpy(autoconf_table[index].proc_name, buf, ch - buf);
				while ((*ch == ' ' || *ch == '\t') && (*ch != '\0'))
					ch ++;
				filename = ch;
				while (*ch != ' ' && *ch != '\t' && *ch != '\0')
					ch ++;
				strncpy(autoconf_table[index].file_name, filename, ch - filename);
				while ((*ch == ' ' || *ch == '\t') && *ch != '\0')
					ch ++;
				version = ch;
				autoconf_table[index].version = atoi(version);
				index++;
			}
			line ++;
		}
		orig_close(fd);
		printk("load autoconf %d entries\n", index);
		for (i=0; i<index; i++) {
			printk("autoconf %d:%s %s %d\n", i, autoconf_table[i].proc_name, autoconf_table[i].file_name, autoconf_table[i].version);
		}
	} else
		printk("Unable to open file %s\n", AUTOCONF_FILENAME);
	set_fs(fs);
    }
    up(&autoconf_lock);
    autoconf_count = index;
    return index;
}
static char *process_whitelist[] = {NULL};

static int access_redirection(const char *filename, char *redirect_filename, int redirect_filename_len);

/*
 * parameters:
 *		filename		user space input
 *		redirect_filename	kernel space output
 */
static int access_redirection(const char *filename, char *redirect_filename, int redirect_filename_len)
{
    char proc_name[TASK_COMM_LEN+1];
    char pathname[MAX_PATH];
    int index;
    int ret = 0;

    get_task_comm_copy(proc_name, current);
    strncpy_from_user(pathname, filename, sizeof(pathname));
    if (proc_name[0] != '\0') {
	printk("access_redirection %s:%s\n", proc_name, pathname);
	strncpy(redirect_filename, pathname, redirect_filename_len);
        for (index = 0; index < autoconf_count; index ++) {
		if (!strcmp(proc_name, autoconf_table[index].proc_name) && !strcmp(pathname, autoconf_table[index].file_name)) {
			snprintf(redirect_filename, redirect_filename_len, "%s.%03d%s", pathname, autoconf_table[index].version, specialversion);
			ret = 1;
			break;
		}
        }
    }
    return ret;
}

#endif // ACCESS_REDIRECT

static int audit_process(void);

static char *no_audit_process[] = {
	"ocasta",
	"cups",
	"am",
	"udevd",
	NULL
};

/*
 * check whether to audit the current process
 */
static int audit_process_ex(struct task_struct *proc)
{
	char proc_name[TASK_COMM_LEN];
	int i, ret = 1;

	get_task_comm_copy(proc_name, proc);
	// prevent dead lock by not auditing some processes
	for (i = 0; no_audit_process[i]; i++) {
		if (strncmp(proc_name, no_audit_process[i], strlen(no_audit_process[i])) == 0) {
			ret = 0;
			break;
		}	
	}	
	return ret;
}

static int audit_process()
{
	struct task_struct *task = current;

	for (task = current; task != &init_task; task = task->parent)
		if (!audit_process_ex(current))
			return 0;
	return 1;
}

/***
 *** Section 1: module operations and top-level file operations
 ***/

int __init
init_module(void)
{
	struct proc_dir_entry *dir;
        struct page *pg;
        pgprot_t prot;
        int i, err;
        
	if(logging == 0) 
		printk(KERN_INFO "Logging to backend has been turned off = %d\n", logging);
	else
		printk(KERN_INFO "Logging to backend has been turned on = %d\n", logging);
	memset((void *)&auditdata, 0, sizeof(struct auditdata_global));
        auditdata.rw_type = AUDIT_RW_INF;
        auditdata.max_ready_pages = MAX_READY_PAGES;
        auditdata.max_free_pages = MAX_FREE_PAGES;
	auditdata.audit_mode = 0;
        INIT_LIST_HEAD(&auditdata.free_list);
        INIT_LIST_HEAD(&auditdata.active_list);
        INIT_LIST_HEAD(&auditdata.ready_list);
        INIT_LIST_HEAD(&auditdata.send_list);
        auditdata.alloc_pgnode = list_entry(&auditdata.active_list,
					    struct pgnode, list);
        /* Locate sys_call_table in kernel */
        sys_call_table = (void **)locate_sys_call_table();
        if (!sys_call_table) {
                printk(KERN_ERR "auditmodule: unable to find syscall table\n");
                return -EBUSY;
        }
#ifdef DEBUG_AUDIT
        /* this will not work when running two ocasta modules */
        /* sanity check */
        if (sys_call_table[__NR_close] != sys_close) {
                printk(KERN_ERR "auditmodule: syscall table is bad\n");
                return -EBUSY;
        }
#endif /* DEBUG_AUDIT */
        printad("auditmodule: found syscall table at address = %p\n",
		sys_call_table);

#ifndef GET_SYMBOL
        do_execve_fn = do_execve;
	lookup_address = lookup_address;
#ifdef SOLITUDE
        ext3_sops_fn = ext3_sops;
#endif /* SOLITUDE */
        do_sendfile_fn = do_sendfile;
#else
        if (get_symbol("do_execve", (void **)&do_execve_fn) < 0) {
		printk(KERN_INFO "get_symbol on do_exeve failed\n");
		return -EINVAL;
        }
        if (get_symbol("lookup_address", (void **)&lookup_address_fn) < 0) {
		printk(KERN_INFO "get_symbol on lookup_address failed\n");
		return -EINVAL;
        }
#ifdef SOLITUDE
        if (get_symbol("ext3_sops", (void **)&ext3_sops_fn) < 0) {
                return -EINVAL;
        }
#endif /* SOLITUDE */
        if (get_symbol("do_sendfile", (void **)&do_sendfile_fn) < 0) {
                return -EINVAL;
        }

#endif

        /* fix kernel permissions for two pages */
        pg = virt_to_page(sys_call_table);
        prot.pgprot = VM_READ | VM_WRITE | VM_EXEC; /* R-W-X */
#if 0
        err = change_page_attr(pg, 2, prot);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	err = change_page_attr_set((unsigned long)sys_call_table & PAGE_MASK, 2, __pgprot(_PAGE_RW));
#else
        err = change_page_attr_ex(pg, 2, prot);
#endif
#endif
	if (err < 0) {
                printk(KERN_ERR "auditmodule: Unable to change permission for sys_call_table: %d\n", err);
		return -EBUSY;
	}
#ifdef DEBUG_AUDIT
        printad("auditmodule: try writing syscall table....\n");
        /* test if we can write to the sys_call_table */
        sys_call_table[__NR_close] = sys_close;
#endif /* DEBUG_AUDIT */

        for (i = 0; i < MAXAUDIT; i++) {
                struct sys_call_data *data;

                data = &sys_call_data[i];
                if (data->orig_syscall)
                        *(data->orig_syscall) = NULL;
        }

        /* audit dev */
        dir = create_proc_entry(AUDIT_DEV, S_IRUSR | S_IWUSR, NULL);
        if (!dir)
                return -1;
        //dir->owner = THIS_MODULE;
        dir->proc_fops = &file_ops;

        /* audit info dev */
        dir = create_proc_entry(AUDIT_INFO, S_IRUGO | S_IWUSR, NULL);
        if (!dir) {
                goto audit_dev;
        }
        //dir->owner = THIS_MODULE;
        dir->proc_fops = &info_ops;

	/* snapshot code */
        dir = create_proc_entry(AUDIT_SNAPSHOT, S_IRUSR | S_IWUSR, NULL);
        if (!dir) {
                goto info_dev;
        }
        //dir->owner = THIS_MODULE;
        dir->proc_fops = &snapshot_ops;

#ifdef SOLITUDE
        /* solitude code */
        dir = create_proc_entry(AUDIT_SOLITUDE, S_IRUSR | S_IWUSR, NULL);
        if (!dir) {
                goto snapshot_dev;
        }
        dir->owner = THIS_MODULE;
        dir->proc_fops = &solitude_ops;
#endif /* SOLITUDE */

        audit_register_oom();
        printk(KERN_INFO "auditmodule%s: version %d.%d.%d initialized\n",
               OCASTA_VER, AUDITMODULE_MAJOR_VERSION, 
               AUDITMODULE_MINOR_VERSION, AUDITMODULE_PATCH_VERSION);
        return 0;
#ifdef SOLITUDE
  snapshot_dev:
        remove_proc_entry(AUDIT_SNAPSHOT, NULL);
#endif /* SOLITUDE */
  info_dev:
        remove_proc_entry(AUDIT_INFO, NULL);
  audit_dev:
        remove_proc_entry(AUDIT_DEV, NULL);
        return -1;

}

void __exit
cleanup_module(void)
{
        printk(KERN_INFO "auditmodule%s: exiting\n", OCASTA_VER);
        down(&audit_lock);
        ASSERT_AUDIT(auditdata.task == NULL);
        ASSERT_AUDIT(auditdata.fp == NULL);
	ASSERT_AUDIT(auditdata.datafp == NULL);
        /* remove the proc entry */
        remove_proc_entry(AUDIT_DEV, NULL);
        remove_proc_entry(AUDIT_INFO, NULL);
        remove_proc_entry(AUDIT_SNAPSHOT, NULL);
#ifdef SOLITUDE
        remove_proc_entry(AUDIT_SOLITUDE, NULL);
#endif /* SOLITUDE */
        up(&audit_lock);
        audit_unregister_oom();
        printad("auditmodule: exited\n");
}

static int
auditmodule_ioctl(struct inode *node, struct file *the_file,
                  unsigned int command, unsigned long arg)
{
        int err = -EINVAL;

        switch (command) {
        case AUDIT_SEND: /* start the sending process. */
		printk("auditmodule_ioctl AUDIT_SEND %lu\n", arg);
		err = audit_start(arg);
                break;
#ifndef VERSIONING
	case AUDIT_SET_DATA_FILE:
		printk("auditmodule_ioctl AUDIT_SET_DATA_FILE %lu\n", arg);
		err = audit_set_data_file(arg);
		break;
	case AUDIT_SET_DATA_FILE_NAME:
		printk("auditmoudle_ioctl AUDIT_SET_DATA_FILE_NAME %s\n", (char *)arg);
		err = audit_set_data_file_name((char *)arg);
		break;
#endif /* VERSIONING */
	case AUDIT_SET_WORK_DIR:
		printk("auditmodule_ioctl AUDIT_SET_WORK_DIR %s\n", (char *)arg);
		err = audit_set_work_dir((char *)arg);
		break;
	case AUDIT_SWITCH:
		down(&audit_lock);	
		err = audit_switch();
		up(&audit_lock);
		break;
	case AUDIT_STOP:
		printk("auditmodule_ioctl AUDIT_STOP\n");
#ifdef VERSIONING
        	auditdata.stop = 1;
        	wake_up(&sender_queue);
#else
		down(&audit_lock);
		audit_off();
        	auditdata.force = 1;
		auditdata.stop = 1;	
		up(&audit_lock);
        	wake_up(&sender_queue);
#endif
		err = 0;
		break;
	case AUDIT_SHOW_VERSION_LOG:
		down(&audit_lock);
		auditdata.show_version_log = arg;
		up(&audit_lock);
		err = 0;
		break;
        case AUDIT_SET_MAX_READY_PAGES:
                if (arg >= 1) {
			down(&audit_lock);
                        auditdata.max_ready_pages = arg;
			up(&audit_lock);
			err = 0;
		}
                break;
        case AUDIT_SET_MAX_FREE_PAGES:
                if (arg >= 1) {
			down(&audit_lock);
                        auditdata.max_free_pages = arg;
			up(&audit_lock);
			err = 0;
		}
                break;
#ifdef ACCESS_REDIRECT
	case AUDIT_LOAD_AUTOCONF:
		err = load_autoconf();
		break;
#endif
        case AUDIT_SET_RW_DATA:
                switch (arg) {
                case AUDIT_RW_INF:
                case AUDIT_RW_NONE:
                case AUDIT_RW_SET:
			down(&audit_lock);
                        auditdata.rw_type = arg;
			up(&audit_lock);
			err = 0;
                        break;
                }
                break;
        }
        return err;
}

static int
nl_send_data(struct sock *sk, pid_t pid, int type, void *data, int len)
{
	struct nlmsghdr *nlh = NULL;
	struct sk_buff *skb = NULL;
	int err = -1, retry = 0;

	//printk(KERN_INFO "%s: size=%d\n", __FUNCTION__, len);
	skb = alloc_skb(NLMSG_SPACE(len), GFP_KERNEL);
	if (skb == NULL) {
		printk(KERN_INFO "%s: allocating skb failed\n", __FUNCTION__);
		return err;
	}
	//memset(skb, 0, NLMSG_SPACE(len));
	nlh = NLMSG_PUT(skb, 0, 1, type, len);
	//nlh = nlmsg_put(skb, 0, 1, type, len, 0);
	memcpy(NLMSG_DATA(nlh), data, len);

	//NETLINK_CB(skb).pid = 0;
	//NETLINK_CB(skb).dst_group = 1;
	//err = netlink_broadcast(sk, skb, 0, 1, GFP_KERNEL);

	NETLINK_CB(skb).pid = 0;
	NETLINK_CB(skb).dst_group = 0;
	do {
		//err = netlink_unicast(sk, skb, pid, MSG_DONTWAIT);
		err = netlink_unicast(sk, skb, pid, 0);
		if (err == -EAGAIN) {
			retry++;
			printk(KERN_INFO "%s: netlink_unicast (pid:%d len:%d) returned %d retry %d\n", __FUNCTION__, pid, len, err, retry);
			if (retry == 3)
				break;
		}
			
	} while (err == -EAGAIN);

	if (err >= 0)
		err = len;
	else
		printk(KERN_INFO "%s: netlink_unicast (pid:%d len:%d) returned %d\n", __FUNCTION__, pid, len, err);
	return err;
nlmsg_failure:
	printk(KERN_INFO "%s: NLMSG_PUT failed\n", __FUNCTION__);
	kfree_skb(skb);
	return err;
}

static void
nl_data_ready(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = NULL;

	if (skb == NULL) {
		printk(KERN_INFO "%s:skb is NULL\n", __FUNCTION__);
		return;
	}
	nlh = (struct nlmsghdr *)skb->data;
	printk(KERN_INFO "%s: received netlink message from pid:%d, len=%d\n", __FUNCTION__, nlh->nlmsg_pid, nlh->nlmsg_len);
	auditdata.rcvpid = nlh->nlmsg_pid;
}

static int
audit_start(unsigned long arg)
{
	int err = -EBUSY;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	if (!try_module_get(THIS_MODULE)) {
		err = -ENODEV;
                return err;
	}
#else /* LINUX_VERSION_CODE */
        MOD_INC_USE_COUNT;
#endif /* LINUX_VERSION_CODE */

        down(&audit_lock);
	auditdata.nl_sk = netlink_kernel_create(&init_net, 17, 0, nl_data_ready, NULL, THIS_MODULE);
	if (auditdata.nl_sk == NULL) {
		printk(KERN_INFO "%s: creating socket failed\n", __FUNCTION__);
		up(&audit_lock);
		return -1;
	}

        if (auditdata.fp != NULL) {
                up(&audit_lock);
                return err;
        }
        ASSERT_AUDIT(list_empty(&auditdata.free_list));
        ASSERT_AUDIT(list_empty(&auditdata.active_list));
        ASSERT_AUDIT(list_empty(&auditdata.ready_list));
        ASSERT_AUDIT(list_empty(&auditdata.send_list));

#ifdef VERSIONING
	audit_on();
	err = 0;
#else
        err = audit_set_output_file(arg);
	if (err >= 0)
		audit_on();
#endif /* VERSIONING */
        up(&audit_lock);
        if (err < 0) {
                return err;
        }
        printad("auditmodule: about to start kernel thread\n");
        err = kernel_thread(audit_thread, NULL, 
                            (CLONE_FS | CLONE_FILES | CLONE_SIGHAND));
        if (err < 0) {
                if (auditdata.fp) {
                        fput(auditdata.fp);
                        auditdata.fp = NULL;
                }
		if (auditdata.datafp) {
			fput(auditdata.datafp);
			auditdata.datafp = NULL;
		}
                return err;
        }
         /* store process that opened the device */
        down(&audit_lock);
        auditdata.task = pid_task(find_vpid(err), PIDTYPE_PID);
        up(&audit_lock);

	if (auditdata.task == NULL)
		return -1;
        printk(KERN_INFO "ocasta_module%s: process %d opens device "
               "/proc/%s\n", OCASTA_VER, auditdata.task->pid, AUDIT_DEV);
#ifdef CONFIG_AUDIT_MMAP
        old_audit_mmap_write_partial = audit_mmap_write_partial;
        audit_mmap_write_partial = audit_mmap_write_partial_ocasta;
	old_audit_mmap_read_partial = audit_mmap_read_partial;
	audit_mmap_read_partial = audit_mmap_read_partial_ocasta;
#endif
        return 0;
}

#ifndef VERSIONING
static int
audit_set_output_file(unsigned long arg)
{
        int retval = 0;
        struct file *file;

        file = fget(arg);
        if (!file)
                return -EBADF;
        if (!(file->f_mode & FMODE_WRITE)) {
                retval = -EBADF;
                goto out;
        }
        if (!file->f_op) {
                retval = -EINVAL;
                goto out;
        }
        if (!file->f_op->write && !file->f_op->sendpage) {
                retval = -EINVAL;
                goto out;
        }
        auditdata.fp = file;
        return retval;
 out:
        fput(file);
        return retval;
}

static int
audit_set_data_file(unsigned long arg)
{
        int retval = 0;
        struct file *file;

        file = fget(arg);
        if (!file)
                return -EBADF;
        if (!(file->f_mode & FMODE_WRITE)) {
                retval = -EBADF;
                goto out;
        }
        if (!file->f_op) {
                retval = -EINVAL;
                goto out;
        }
        if (!file->f_op->write && !file->f_op->sendpage) {
                retval = -EINVAL;
                goto out;
        }
        auditdata.datafp = file;
	auditdata.dataseq = 1;
        return retval;
 out:
        fput(file);
        return retval;
}

static int
audit_set_data_file_name(char *arg)
{
	int retval = 0;

	if (arg == NULL) {
		retval = -EINVAL;
		goto out;
	}
	strncpy(auditdata.data_file_name, arg, sizeof(auditdata.data_file_name));
 out:
	return retval;
}

#endif /* VERSIONING */

static int
audit_set_work_dir(char *arg)
{
	int retval = 0;

	if (arg == NULL) {
		retval = -EINVAL;
		goto out;
	}
	strncpy(auditdata.work_dir, arg, sizeof(auditdata.work_dir));
	snprintf(auditdata.shadow_dir, sizeof(auditdata.shadow_dir), "%s/%s", arg, SHADOW_DIR);
	auditdata.shadow_dir_len = strlen(auditdata.shadow_dir);
 out:
	return retval;
}

static void
audit_stop()
{
	char *done_msg = "Ocasta: stopped logging";

#ifdef CONFIG_AUDIT_MMAP
        audit_mmap_write_partial = old_audit_mmap_write_partial;
	audit_mmap_read_partial  = old_audit_mmap_read_partial;
#endif
 restart:
        down(&audit_lock);
        if (auditdata.sending_active ||
            atomic_read(&auditdata.sendfile_active)) {
                /* wait for sends */
                DECLARE_WAIT_QUEUE_HEAD(wq);
                printad("%s: sleeping\n", __FUNCTION__);
                up(&audit_lock);
                sleep_for(&wq, HZ/100); /* wait for 10 ms */
                goto restart; /* try again */
        }
        if (auditdata.fp) {
        	fput(auditdata.fp);
        	auditdata.fp = NULL; /* turns off auditing */
        	auditdata.fd = -1;
        }
        if (auditdata.datafp) {
		fput(auditdata.datafp);
		auditdata.datafp = NULL;
		auditdata.datafd = -1;
        }
        /* do the work */
	audit_off();
	audit_wait_active_pages();
	if (auditdata.nl_sk) {
		nl_send_data(auditdata.nl_sk, auditdata.rcvpid, NLMSG_DONE, done_msg, strlen(done_msg));

		sock_release(auditdata.nl_sk->sk_socket);	
	}
        auditdata.task = NULL;

        printk(KERN_INFO "auditmodule%s: shutdown: free pages = %d, "
	       "active pages = %d, ready pages = %d, send pages = %d, "
	       "allocation position = %d\n", OCASTA_VER, 
               auditdata.nr_free_pages, auditdata.nr_active_pages, 
               auditdata.nr_ready_pages, auditdata.nr_send_pages,
               auditdata.alloc_pos);
	audit_free_pages(&auditdata.free_list, &auditdata.nr_free_pages);
	audit_free_pages(&auditdata.active_list, &auditdata.nr_active_pages);
	audit_free_pages(&auditdata.ready_list, 
                         (int *)&auditdata.nr_ready_pages);
	audit_free_pages(&auditdata.send_list, &auditdata.nr_send_pages);
        auditdata.rw_type = AUDIT_RW_INF;
        auditdata.alloc_pgnode = list_entry(&auditdata.active_list,
					    struct pgnode, list);
        auditdata.alloc_pos = 0;
        up(&audit_lock);
        
        /* auditing is being stopped. start all waiting processes */
        wake_up(&audit_queue);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	module_put(THIS_MODULE);
#else /* LINUX_VERSION_CODE */
        MOD_DEC_USE_COUNT;
#endif /* LINUX_VERSION_CODE */
}

/***
 *** Section 2: event allocation and deallocation routines
 ***/

/* Allocate a new pgnode
 * Move pages from free list to active list. */
static int
alloc_pgnode(void)
{
        struct list_head *free_head = &auditdata.free_list;
        struct pgnode *pgnode;

	auditdata.alloc_pos = 0;
	pgnode = list_entry(free_head->next, struct pgnode, list);
	if (!list_empty(free_head)) {
		/* move free pgnode to active list */
		list_move_tail(free_head->next, &auditdata.active_list);
		auditdata.nr_free_pages--;
		auditdata.nr_active_pages++;
		auditdata.alloc_pgnode = pgnode;
#ifdef SOLITUDE
                pgnode->marker_flag = 0; /* for safety */
#endif /* SOLITUDE */
		printad("%s: allocated free page\n", __FUNCTION__);
		return 1;
	}
	if (!(pgnode = (struct pgnode *)kmalloc(sizeof(struct pgnode),
						GFP_KERNEL)))
		return 0;
	if (!(pgnode->page = alloc_pages(GFP_KERNEL, 0))) {
		kfree(pgnode);
		return 0;
	}
	atomic_set(&pgnode->count, 0);
#ifdef SOLITUDE
        pgnode->marker_flag = 0;
#endif /* SOLITUDE */
	list_add_tail(&pgnode->list, &auditdata.active_list);
	auditdata.nr_active_pages++;
	auditdata.nr_allocated_pages++;
	auditdata.alloc_pgnode = pgnode;
	printad("%s: allocated new page\n", __FUNCTION__);
	return 1;
}

/* Allocate space for this system call event */
/* slow path, call within audit_lock() */
static void
__audit_event_alloc(struct auditevent *e)
{
        struct list_head *head = &auditdata.active_list;
        struct pgnode *orig_alloc_pgnode = auditdata.alloc_pgnode;
        int orig_alloc_pos = auditdata.alloc_pos;
        int size = e->size;
	int minsz;

	while (size > 0) {
                if (list_empty(head) || (auditdata.alloc_pos == PAGE_SIZE))
			if (!alloc_pgnode())
				goto out;
                ASSERT_AUDIT(auditdata.alloc_pos < PAGE_SIZE);
		minsz = min_t(int, size, PAGE_SIZE - auditdata.alloc_pos);
		if (!e->node) {
			e->node = auditdata.alloc_pgnode;
			e->offset = auditdata.alloc_pos;
		}
		auditdata.alloc_pos += minsz;
		atomic_inc(&auditdata.alloc_pgnode->count);
		size -= minsz;
                if (auditdata.alloc_pos == PAGE_SIZE)
			if (!alloc_pgnode())
				goto out;
	}
        return;
 out:
        printad("%s: error allocating a new page\n", __FUNCTION__);
        /* memory pressure. deallocate all pages not being written */
        atomic_dec(&orig_alloc_pgnode->count);
	while (orig_alloc_pgnode->list.next != head) {
                struct pgnode *pgnode = list_entry(orig_alloc_pgnode->list.next,
                                                   struct pgnode, list);
		atomic_dec(&pgnode->count);
		audit_free_pgnode(pgnode);
		auditdata.nr_active_pages--;
	}
	audit_free_pages(&auditdata.free_list, &auditdata.nr_free_pages);	
        auditdata.alloc_pgnode = orig_alloc_pgnode;
        auditdata.alloc_pos = orig_alloc_pos;
        e->node = NULL;
}

/* Allocate space for this system call event */
static int
audit_event_alloc(struct auditevent *e)
{
        e->node = NULL;
        e->try_sending_pages = 0;

	wait_event(audit_queue, (auditdata.nr_ready_pages < 
		   auditdata.max_ready_pages));
        down(&audit_lock);
        if (auditdata.fp) {
                if (likely(!list_empty(&auditdata.active_list) && 
                           (e->size < PAGE_SIZE - auditdata.alloc_pos))) {
                        e->node = auditdata.alloc_pgnode;
			e->offset = auditdata.alloc_pos;
                        auditdata.alloc_pos += e->size;
                        atomic_inc(&auditdata.alloc_pgnode->count);
                } else {
                        __audit_event_alloc(e);
                }
        }
        up(&audit_lock);
        return e->node ? 1 : 0;
}

#ifdef SOLITUDE
/* Allocate a page-aligned page. */
static int
audit_event_alloc_page_aligned(struct auditevent *e)
{
        e->node = NULL;
        e->try_sending_pages = 0;
        printad("%s: starts\n", __FUNCTION__);
	wait_event(audit_queue, (auditdata.nr_ready_pages < 
		   auditdata.max_ready_pages));
        down(&audit_lock);

        if (auditdata.fp) {
                if (likely(e->size <= PAGE_SIZE - auditdata.alloc_pos)) {
                        /* alignment header in current page */
                        e->size = PAGE_SIZE - auditdata.alloc_pos + PAGE_SIZE;
                } else if (auditdata.alloc_pos != PAGE_SIZE) {
                        /* alignment header is split across an extra page */
                        e->size = PAGE_SIZE - auditdata.alloc_pos + PAGE_SIZE + 
                                PAGE_SIZE;
                } else {
                        /* don't need to have alignment header */
                        e->size = PAGE_SIZE;
                }
                __audit_event_alloc(e);
        }
        up(&audit_lock);
        return e->node ? 1 : 0;
}
#endif /* SOLITUDE */

/* Call within audit_lock */
static void
audit_free_pgnode(struct pgnode *entry)
{
        __free_page(entry->page);
	auditdata.nr_allocated_pages--;
        kfree(entry);
}

/* Call within audit_lock */
static void
audit_free_pages(struct list_head *head, int *nr)
{
	struct list_head *pos = NULL, *q = NULL;
	struct pgnode *entry = NULL;

	list_for_each_safe(pos, q, head) {
		entry = list_entry(pos, struct pgnode, list);
		list_del(pos);
                audit_free_pgnode(entry);
                (*nr)--;
        }
        ASSERT_AUDIT(*nr == 0);
}

/* Call within audit_lock */
static void
audit_wait_active_pages()
{
        struct list_head *head = &auditdata.active_list;
	struct pgnode *pgnode = list_entry(head->next, struct pgnode, list);
	DECLARE_WAIT_QUEUE_HEAD(wq);
        int tries = 1;

        while (!list_empty(head) && tries < 256) {
		audit_move_to_ready_list();
		if (auditdata.alloc_pgnode == pgnode &&
		    atomic_read(&auditdata.alloc_pgnode->count) == 0) {
			break;
		}
		printk(KERN_INFO "%s: waiting for active pages\n",
		       __FUNCTION__);
                /* Processes are actively using our system calls. Sleep for
                 * some time so that processes will hopefully stop doing so. */
                up(&audit_lock);
		/* sleep for increasing times */
                sleep_for(&wq, HZ/100 * tries);
                tries = tries << 1;
                down(&audit_lock);
        }
        if (tries >= 256) {
                printk(KERN_CRIT "%s: bug: active list not drained\n",
		       __FUNCTION__);
        }
}

/***
 *** Section 3: event copying routines
 ***/

/* slow path */
static int
__audit_write_event(const void *data, int size, struct auditevent *e, int user)
{
	struct list_head *entry;
	int minsz; int ret = 0;

	do {
		if (e->offset == PAGE_SIZE) {
			printad("%s: get next page\n", __FUNCTION__);
			down(&audit_lock);
			atomic_dec(&(e->node)->count);
			entry = e->node->list.next;
			ASSERT_AUDIT(entry != &auditdata.active_list);
			up(&audit_lock);
			e->node = list_entry(entry, struct pgnode, list);
			e->offset = 0;
		}
		minsz = min_t(int, size, PAGE_SIZE - e->offset);
		if (user) {
			ret = copy_from_user(page_address((e->node)->page) + 
				             e->offset, data, minsz);
		} else {
			memcpy(page_address((e->node)->page) + e->offset,
			       data, minsz);
		}
		printad("%s: offset = %d, minsz = %d\n", __FUNCTION__,
			e->offset, minsz);
		e->offset += minsz;
		data += minsz;
		size -= minsz;
        } while (size > 0);
	e->try_sending_pages = 1;
        return ret;
}

static inline void
audit_write_event(const void *data, int size, struct auditevent *e)
{
        e->size -= size;
        if (size <= PAGE_SIZE - e->offset) {
                memcpy(page_address((e->node)->page) + e->offset, data, size);
                e->offset += size;
		return;
        }
	__audit_write_event(data, size, e, 0);
}

static inline int
audit_write_user_event(const void *data, int size, struct auditevent *e)
{
        e->size -= size;
        if (size <= PAGE_SIZE - e->offset) {
                int ret = copy_from_user(page_address((e->node)->page) +
                                         e->offset, data, size);
                e->offset += size;
		return ret;
        }
	return __audit_write_event(data, size, e, 1);
}

/* Generic auditing routine without event timestamp. */
static inline int
audit_generic_wotime(header_token *event, int event_size, int nr_blocks,
		     int datalen)
{
	event->pid = current->pid;
//        event->pid_time = PROCESS_START_TIME(current);
        event->event_size = event_size - sizeof(header_token);
        event->num_blocks = nr_blocks;
        event->data_size = datalen;
        return event_size + datalen;
}

/* Generic auditing routine, used by all audit functions. */
static int
audit_generic(header_token *event, int event_size, int nr_blocks, int datalen)
{
        do_gettimeofday(&(event->time));
	return audit_generic_wotime(event, event_size, nr_blocks, datalen);
}

/***
 *** Section 4: event sending routines
 ***/

/* Try sending pages ... */
static inline void
audit_try_sending_pages(void)
{
        down(&audit_lock);
        printad("%s: start\n", __FUNCTION__);
	audit_move_to_ready_list();
	/* replace first condition with list_empty(&auditdata.ready_list) for
	 * smoothed sending */
	
        if (!auditdata.sending_active && WAKEUP_COND) {
		up(&audit_lock);
                printad("%s: wake_up\n", __FUNCTION__);
                wake_up(&sender_queue);
		return;
	}
	up(&audit_lock);
}

/* Move pages from active list to ready list */
static void
audit_move_to_ready_list(void)
{
        struct list_head *head = &auditdata.active_list;
        struct pgnode *pgnode;

        while (!list_empty(head)) {
                pgnode = list_entry(head->next, struct pgnode, list);
                if (pgnode == auditdata.alloc_pgnode ||
                    atomic_read(&pgnode->count) != 0) {
                        break; /* no more pages to move to ready list */
                }
                list_move_tail(head->next, &auditdata.ready_list);
                auditdata.nr_active_pages--;
                auditdata.nr_ready_pages++;
                printad("%s: nr_ready_pages = %d\n", __FUNCTION__, 
                        auditdata.nr_ready_pages);
        }
}

/* The core routine for sending data. Move pages from ready list to sending
 * list. */
/* Important: this routine should be called in the context of the audit_daemon
 * and not in the context of any arbitrary process because when a signal is
 * sent to the arbitrary process, then audit_sendpage() will return with the
 * error ERESTARTSYS. At that point, it is hard to guarantee that this routine
 * has made any progress which can lead to a deadlock at the audit_queue.
 */
/* Important: if the audit_daemon gets a spurious signal then auditing will
 * stop. */
static inline int
audit_move_to_sending_list(void)
{
        struct list_head *ready_head = &auditdata.ready_list;
        struct pgnode *pgnode;
	int ret = 0;
#ifdef SOLITUDE
        snapshot_class* sc= NULL;
#endif /* SOLITUDE */

	down(&audit_lock);
	auditdata.sending_active = 1;
        auditdata.force = 0;
	while (!list_empty(ready_head)) {
                pgnode = list_entry(ready_head->next, struct pgnode, list);
                up(&audit_lock);
                /* we don't need to lock fp and page because of the
                 * sending_active flag. See also audit_stop */

#ifdef SOLITUDE
                if(pgnode->marker_flag == 1){
                        sc = (snapshot_class *) page_address(pgnode->page);
                        /*
                        printas("%s BEFORE marker_flag %d event_class %d \n:",
                               __FUNCTION__, pgnode->marker_flag, 
                               sc->t_header.event_id);
                        printas("%s:skip_len %d,file_len %d, "
                               "in_file 0x%x\n" , __FUNCTION__, sc->skip_len, 
                               sc->file_len, (unsigned int)sc->in_file);
                        */
                }
#endif /* SOLITUDE */
		if(logging)
	                ret = audit_sendpage(auditdata.fp, pgnode->page);
#ifdef SOLITUDE
                if(pgnode->marker_flag == 1){
                        /*
                        printas("%s AFTER marker_flag %d event_class %d \n:",
                               __FUNCTION__, pgnode->marker_flag, 
                               sc->t_header.event_id);
                        printas("%s:skip_len %d,file_len %d, "
                               "in_file 0x%x\n" , __FUNCTION__, sc->skip_len, 
                               sc->file_len, (unsigned int)sc->in_file);
                        */
                        /* send file snapshot, this is a blocking call. */
                        if(logging)                                                
	                        ret = do_snapshot_sendfile(sc);
                        printas("Sendfile with return value: %d\n", ret);
                        pgnode->marker_flag = 0;
                        /* Release the reference to the page */
                        /* wakeup send_original_file */
                        wake_up((wait_queue_head_t*)sc->wq);
                        //printas("Send original file woken up: %d\n", ret);
                }
                

#endif /* SOLITUDE */

                down(&audit_lock);
                if (ret < 0) {
			goto out;
		}
                list_move_tail(ready_head->next, &auditdata.send_list);
                auditdata.nr_ready_pages--;
                auditdata.nr_send_pages++;
        }
	ASSERT_AUDIT(auditdata.nr_ready_pages == 0);
	audit_move_to_free_list();
 out:
	auditdata.sending_active = 0;
	up(&audit_lock);
	printad("%s: wake_up\n", __FUNCTION__);
	wake_up(&audit_queue);
	return ret;
}

/* Move pages from sending list to free list */
static void
audit_move_to_free_list(void)
{
	struct list_head *send_head = &auditdata.send_list;
	struct list_head *pos = NULL, *q = NULL;
        struct pgnode *pgnode = NULL;

	list_for_each_safe(pos, q, send_head) {
		pgnode = list_entry(pos, struct pgnode, list);
		if (page_count(pgnode->page) > 1) {
			break; /* no more pages can be moved to free list */
		}
		if (auditdata.nr_free_pages <= auditdata.max_free_pages) {
			list_move_tail(pos, &auditdata.free_list);
			auditdata.nr_free_pages++;
		} else { /* free page */
			list_del(pos);
			audit_free_pgnode(pgnode);
		}
		auditdata.nr_send_pages--;
	}
}

/* Function can block. Don't hold locks. */
static int
audit_sendpage(struct file *file, struct page *page)
{
        int offset = 0;
        int ret = 0;
	//char *dat_msg = "DATA";

        if (!file || !page)
                return -EBADF;
        do {
#ifdef USE_NETLINK
		char *kaddr = kmap(page);
		//ret = nl_send_data(auditdata.nl_sk, auditdata.rcvpid, 0, kaddr + offset, 1024);
		ret = nl_send_data(auditdata.nl_sk, auditdata.rcvpid, 0, kaddr + offset, PAGE_SIZE - offset);
		// For testing
		//ret = nl_send_data(auditdata.nl_sk, auditdata.rcvpid, 0, dat_msg, strlen(dat_msg));
		kunmap(page);
#else
                if (file->f_op->sendpage) {
                        ret = file->f_op->sendpage(file, page, offset,
                                                   PAGE_SIZE - offset,
                                                   &file->f_pos, 0);
                } else {
                        char *kaddr;
                        mm_segment_t old_fs;

                        old_fs = get_fs();
                        set_fs(KERNEL_DS);
                        kaddr = kmap(page);
                        ret = file->f_op->write(file, kaddr + offset,
                                                PAGE_SIZE - offset,
                                                &file->f_pos);
                        kunmap(page);
                        set_fs(old_fs);
                }
#endif
		if (ret > 0) {
			offset += ret;
		}
                if (offset == PAGE_SIZE)
                        return PAGE_SIZE; /* done */
        } while (ret > 0);
        /* ret <= 0 is some error */
        printk(KERN_ERR "%s: error = %d\n", __FUNCTION__, ret);
        return ret;
}

void
audit_fd_close(int fd, struct file *fp)
{
	struct files_struct *files;
	struct fdtable *fdt;

        files = current->files;
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	ASSERT_AUDIT(fd < fdt->max_fds);
	ASSERT_AUDIT(fdt->fd[fd] == fp);
	rcu_assign_pointer(fdt->fd[fd], NULL);
	spin_unlock(&files->file_lock);
        put_unused_fd(fd);
                
}

#ifdef INIT_SIGHAND
#define TASK_SIGLOCK &current->sighand->siglock
#else
#define TASK_SIGLOCK &current->sigmask_lock
#endif

static int
audit_thread(void *arg)
{
	int ret = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        daemonize("ocasta");
#else
        old_sigset_t blocked;
        daemonize();
        /* Block and flush all signals */
        blocked = (unsigned long)-1;
        spin_lock_irq(TASK_SIGLOCK);
        sigaddsetmask(&current->blocked, blocked);
        spin_unlock_irq(TASK_SIGLOCK);
        flush_signals(current);
#endif

#ifndef VERSIONING
        /* daemonize closes all file descriptors */
        /* get a new unused fd */
	down(&audit_lock);
        auditdata.fd = get_unused_fd();
        if (auditdata.fd < 0) {
                ret = auditdata.fd;
                up(&audit_lock);
                goto out;
        }
        /* make auditdata.fd accessible via auditdata.fp */
        fd_install(auditdata.fd, auditdata.fp);
	auditdata.datafd = get_unused_fd();
	if (auditdata.datafd < 0) {
		ret = auditdata.datafd;
		up(&audit_lock);
		goto out;
	}
        /* make auditdata.datafd accessible via auditdata.datafp */
	fd_install(auditdata.datafd, auditdata.datafp);
        up(&audit_lock);

        //printad("auditmodule: in audit_thread\n");
        printk("auditmodule: in audit_thread\n");
        do {
		if ((ret = audit_move_to_sending_list()) < 0)
			break;
		if (auditdata.stop) {
        		printk("%s: audit_stop called\n", __FUNCTION__);
			break;
		}
		ret = wait_event_interruptible(sender_queue, WAKEUP_COND);
        } while (ret >= 0);
        audit_fd_close(auditdata.fd, auditdata.fp);
	audit_fd_close(auditdata.datafd, auditdata.datafp);
 out:
        //printad("%s: audit_stop called\n", __FUNCTION__);
	audit_stop();
	if (ret == -ERESTARTSYS)
		printk("%s: daemon process received a signal\n", __FUNCTION__);
#else
	ret = wait_event_interruptible(sender_queue, auditdata.stop);
        printk("%s: audit_stop called\n", __FUNCTION__);
	audit_stop();
#endif /* VERSIONING */
	return ret;
}

/***
 *** Section 5: /proc/auditinfo
 ***/

/* Prepare the data string for reading. */
static char *
audit_info_makedata(void)
{
        const int info_data_len = 512;
        char *data;
        int pid = 0;

        if ((data = kmalloc(info_data_len, GFP_KERNEL)) == NULL)
                return NULL;
        if (auditdata.task != NULL) {
                pid = auditdata.task->pid;
        }
#ifdef VERSIONING
        snprintf(data, info_data_len,
                 "4N6 version:     %d.%d.%d\n"
                 "Audit process:   %5d\n"
                 "Total pages:     %5d\n"
		 "Work directory:      %s\n"
		 "Show version logs:   %c\n"
	         "Node count:      %5d\n"
                 "Audit mode:      %5d\n",
                 AUDITMODULE_MAJOR_VERSION, AUDITMODULE_MINOR_VERSION,
                 AUDITMODULE_PATCH_VERSION, pid, 
                 auditdata.nr_allocated_pages,
		 auditdata.work_dir,
		 (auditdata.show_version_log? 'Y' : 'N'),
		 node_count,
		 auditdata.audit_mode);
#else
        snprintf(data, info_data_len,
                 "4N6 version:     %d.%d.%d\n"
                 "Audit process:   %5d\n"
                 "Audit active:    %5d\n"
                 "Free pages:      %5d\n"
                 "Active pages:    %5d\n"
                 "Ready pages:     %5d\n"
                 "Sending pages:   %5d\n"
                 "(F+A+R+S) pages: %5d\n"
                 "Total pages:     %5d\n"
                 "Alloc position:  %5d\n"
                 "Audit mode:      %5d\n",
                 AUDITMODULE_MAJOR_VERSION, AUDITMODULE_MINOR_VERSION,
                 AUDITMODULE_PATCH_VERSION, pid, auditdata.fp != 0,
                 auditdata.nr_free_pages, auditdata.nr_active_pages,
		 auditdata.nr_ready_pages, auditdata.nr_send_pages,
		 auditdata.nr_free_pages + auditdata.nr_active_pages +
		 auditdata.nr_ready_pages + auditdata.nr_send_pages,
                 auditdata.nr_allocated_pages,
                 auditdata.alloc_pos,
		 auditdata.audit_mode);
#endif /* VERSIONING */
        return data;
}

/* /proc/auditinfo open */
static int
audit_info_open(struct inode *inode, struct file *file)
{
        char *data;

        down(&audit_lock);
        audit_move_to_ready_list();
        data = audit_info_makedata();
        /* force sending data that has been written until now */
        auditdata.force = 1;
        up(&audit_lock);
        wake_up(&sender_queue);
        if (data == NULL)
                return -ENODEV;
        file->private_data = data;
        return 0;
}

static int
audit_info_close(struct inode *inode, struct file *file)
{
        kfree(file->private_data);
        return 0;
}

static ssize_t
audit_info_read(struct file *file, char *ubuf, size_t length, loff_t *ppos)
{
        int bytes_to_write;
        int pos = *ppos;
        char *data = file->private_data;

        if (length == 0)        // Some users are so twisted.
                return 0;
        if ((bytes_to_write = strlen(data) - pos) <= 0)
                return 0;       // EOF
        if (bytes_to_write >= length)
                bytes_to_write = length;
        if (copy_to_user(ubuf, data + pos, bytes_to_write))
                return -EFAULT;
        *ppos = pos + bytes_to_write;
        return bytes_to_write;
}



/* snapshot code */
static void
fillattr(struct inode *inode, struct custat *stat)
{
        stat->i_dev = GET_INODE_IDEV(inode);
        stat->i_ino = inode->i_ino;
        stat->i_mode = inode->i_mode;
        stat->i_nlink = inode->i_nlink;
        stat->i_uid = inode->i_uid;
        stat->i_gid = inode->i_gid;
        stat->i_igen = inode->i_generation;
        stat->i_taint = 0;
}

static inline int
get_process_start_time(pid_t pid)
{
        int start_time;
        struct task_struct *proc;

        TASKLIST_LOCK;
	proc = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (!proc) {
                TASKLIST_UNLOCK;
                return -ESRCH;
        }
        start_time = PROCESS_START_TIME(proc);
        TASKLIST_UNLOCK;
        return start_time;
}

/* cmd = AUDIT_SNAPSHOT_STAT_CMD:
 *   We use an ioctl to do a lstat call.
 *   The user data contains the path for which we want to do a stat.
 *   We fill this same user data with the custat structure. hack!
 * cmd = AUDIT_SNAPSHOT_PROC_CMD:
 *   We return the start_time for a process.
 */

static int
snapshot_ioctl(struct inode * inode, struct file * filp, unsigned int cmd,
               unsigned long user_data)
{
        struct custat stat;
        pid_t pid;
        int start_time;
        int error = 0;
	struct path path;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
        struct nameidata nd;
#endif
        
        switch (cmd) {
        case AUDIT_SNAPSHOT_STAT_CMD:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
                if ((error = user_lpath((void *)user_data, &path)))
#else
                if ((error = user_path_walk_link((void *)user_data, &nd)))
#endif
                        return error;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
                fillattr(path.dentry->d_inode, &stat);
#else
                fillattr(nd.path.dentry->d_inode, &stat);
#endif
#ifdef SOLITUDE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
                if(file_is_tainted(path.dentry->d_inode)) {
#else
                if(file_is_tainted(nd.dentry->d_inode)) {
#endif
                        stat.i_taint = 1;
                }
#endif /* SOLITUDE */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
		path_put(&path);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
		path_put(&nd.path);
#else
                path_release(&nd);
#endif
#endif
                if (copy_to_user((void *)user_data, &stat,
                                 sizeof(struct custat)))
                        return -EFAULT;
                return 0;

        case AUDIT_SNAPSHOT_STAT_UNTAINT_CMD:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
                if ((error = user_lpath((void *)user_data, &path)))
#else
                if ((error = user_path_walk_link((void *)user_data, &nd)))
#endif
                        return error;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
                fillattr(path.dentry->d_inode, &stat);
#else
                fillattr(nd.dentry->d_inode, &stat);
#endif
#ifdef SOLITUDE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
                if(file_is_tainted(path.dentry->d_inode)) {
                        stat.i_taint = 1;
                        EXT3_I(path.dentry->d_inode)->i_flags &=
                                ~TAINTED_FILE_MASK;
                        mark_inode_dirty(path.dentry->d_inode);
                }
#else
                if(file_is_tainted(nd.dentry->d_inode)) {
                        stat.i_taint = 1;
                        EXT3_I(nd.dentry->d_inode)->i_flags &=
                                ~TAINTED_FILE_MASK;
                        mark_inode_dirty(nd.dentry->d_inode);
                }
#endif
#endif /* SOLITUDE */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
		path_put(&path);
#else               
                path_release(&nd);
#endif
                if (copy_to_user((void *)user_data, &stat,
                                 sizeof(struct custat)))
                        return -EFAULT;
                return 0;

        case AUDIT_SNAPSHOT_PROC_CMD:
                if (copy_from_user(&pid, (void *)user_data, sizeof(pid_t)))
                        return -EFAULT;
                start_time = get_process_start_time(pid);
                if (start_time < 0)
                        return start_time;
                if (copy_to_user((void *)user_data, &start_time, sizeof(int))) {
                        return -EFAULT;
                }
                return 0;
        }
        return -EINVAL;
}

#ifdef SOLITUDE

static int
solitude_ioctl(struct inode * inode, struct file * filp, unsigned int cmd,
               unsigned long user_data)
{
        switch(cmd) {
        case AUDIT_SOLITUDE_START:
                if (!capable(CAP_SYS_CHROOT))
                        return -EPERM;
                /* make this process be an IFS process */
                current->flags |= IFS_PROCESS_MASK;
                ifs_start((struct ifs_capability_set *)user_data);
                return 0;
        case AUDIT_SOLITUDE_COMMIT:
                return solitude_commit(user_data);
        }
        return -EINVAL;
}

#endif /* SOLITUDE */

/***
 *** Section 6: miscellaneous routines
 ***/

static void
audit_on(void)
{
	int i;
        struct sys_call_data *data;

        if (!sys_call_table)
                return;
	if (auditdata.audit_mode != 0)
		return;
	// preserve original entry points
	for (i = 0; i < MAXAUDIT; i++) {
		data = &sys_call_data[i];
                if (!data->audit_this_call)
			continue;
		if (!data->audit_syscall) /* audit_syscall not defined */
			continue;
		if (!data->orig_syscall) /* variable is not defined */
			continue;
		if (*(data->orig_syscall)) /* already on */
			continue;
		printad("%s: getting syscall nr = %d\n", __FUNCTION__,
			data->syscall_nr);
		*(data->orig_syscall) = sys_call_table[data->syscall_nr];
	}
	// overwrite with new entry points
	for (i = 0; i < MAXAUDIT_ON; i++) {
		data = &sys_call_data[i];
                if (!data->audit_this_call)
			continue;
		if (!data->audit_syscall) /* audit_syscall not defined */
			continue;
		if (!data->orig_syscall) /* variable is not defined */
			continue;
		printad("%s: setting syscall nr = %d\n", __FUNCTION__,
			data->syscall_nr);
		sys_call_table[data->syscall_nr] = data->audit_syscall;
	}
	auditdata.audit_mode = 1;
}

static void
audit_off(void)
{
	int i;
        struct sys_call_data *data;

        if (!sys_call_table)
                return;
	if (auditdata.audit_mode != 1)
		return;
	for (i = 0; i < MAXAUDIT; i++) {
		data = &sys_call_data[i];
		if (!data->audit_syscall) /* audit_syscall not defined */
			continue;
		if (!data->orig_syscall) /* variable is not defined */
			continue;
		if (*(data->orig_syscall) == 0) /* already off */
			continue;
		//printad("%s: resetting syscall nr = %d\n", __FUNCTION__,
		//	data->syscall_nr);
		printk("%s: resetting syscall nr = %d\n", __FUNCTION__,
			data->syscall_nr);
		sys_call_table[data->syscall_nr] = *(data->orig_syscall);
		*(data->orig_syscall) = NULL;
	}
	auditdata.audit_mode = 0;
}

static int
audit_switch(void)
{
	if (auditdata.audit_mode == 1)
		audit_off();
	else if (auditdata.audit_mode == 0)
		audit_on();
	return auditdata.audit_mode;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
/* includes definitions of register_oom_notifier and unregister_oom_notifier */
#include <linux/swap.h>
#else
#include <linux/oom.h>
#endif

static int
oom_audit_fn(struct notifier_block *s, unsigned long v, void * d)
{
        int pid = 0;
        down(&audit_lock);
        if (auditdata.task != NULL) {
                pid = auditdata.task->pid;
        }
        printk(KERN_CRIT "4N6 version:     %d.%d.%d\n"
               "Audit process:   %5d\n"
               "Audit active:    %5d\n"
               "Free pages:      %5d\n"
               "Active pages:    %5d\n"
               "Ready pages:     %5d\n"
               "Sending pages:   %5d\n"
               "(F+A+R+S) pages: %5d\n"
               "Total pages:     %5d\n"
               "Alloc position:  %5d\n",
               AUDITMODULE_MAJOR_VERSION, AUDITMODULE_MINOR_VERSION,
               AUDITMODULE_PATCH_VERSION, pid, auditdata.fp != 0,
               auditdata.nr_free_pages, auditdata.nr_active_pages,
               auditdata.nr_ready_pages, auditdata.nr_send_pages,
               auditdata.nr_free_pages + auditdata.nr_active_pages +
               auditdata.nr_ready_pages + auditdata.nr_send_pages,
               auditdata.nr_allocated_pages,
               auditdata.alloc_pos);
        up(&audit_lock);
        return 0;
}

static struct notifier_block oom_audit = {
	.notifier_call = oom_audit_fn,
};

static void
audit_register_oom(void)
{
        register_oom_notifier(&oom_audit);
}

static void
audit_unregister_oom(void)
{
        unregister_oom_notifier(&oom_audit);
}
#else /*  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20) */
static void
audit_register_oom(void)
{
}
static void
audit_unregister_oom(void)
{
}
#endif /*  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20) */

/* Get sys_call_table on x86 machines since it is not exported from the kernel
 * anymore */
static unsigned long *
locate_sys_call_table(void)
{
	struct idt_t {
		unsigned short off1;
		unsigned short sel;
		unsigned char none,flags;
		unsigned short off2;
	} __attribute__ ((packed)) idt;
	long long idtr;
	long idtr_base;
        unsigned long *sys_call_table = 0;
	char *sys_call_asm;
	int i;

        asm ("sidt %0" : "=m" (idtr));
	idtr_base = idtr >> 16;
        /* read-in IDT for 0x80 vector (syscall) */
        idt = *(struct idt_t *)(idtr_base + 8 * 0x80);
	/* sys_call_asm is the assembly of the system call interrupt handler */
        sys_call_asm = (char *)((idt.off2 << 16) | idt.off1);
        for (i = 0; i < 128; i++) { /* look for specific assembly */
		if ((sys_call_asm[i] == '\xff') &&
		    (sys_call_asm[i+1] == '\x14') &&
		    (sys_call_asm[i+2] == '\x85')) {
			sys_call_table = 
				*(unsigned long **)(sys_call_asm + i + 3);
			printk(KERN_INFO "Located sys_call_table at 0x%p\n",
			       sys_call_table);
			break;
		}
	}
        return sys_call_table;
}

#ifdef GET_SYMBOL
/* A hack to get the address of an unexported symbol.
 * This won't work on systems that do not keep function pointers
 * in /proc/kallsyms */

struct kallsym_iter
{
       loff_t pos;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
       unsigned long value;
       unsigned int nameoff;
       char type;
       char name[128];
       char module_name[64 - sizeof(unsigned long)];
       int exported;
#else
       struct module *owner;
       unsigned long value;
       unsigned int nameoff; /* If iterating in core kernel symbols */
       char type;
       char name[128];
#endif
};

static int __init
get_symbol(char *symbol, void **addr)
{
        struct file *kallsyms;
        struct seq_file *seq;
        struct kallsym_iter *iter;
        loff_t pos = 0;
        int ret = -EINVAL;

        kallsyms = filp_open("/proc/kallsyms", O_RDONLY, 0);
        if (!kallsyms || IS_ERR(kallsyms)) {
                if (IS_ERR(kallsyms))
                        ret = PTR_ERR(kallsyms);
                printk(KERN_WARNING "/proc/kallsyms: open: %d\n", ret);
                goto done;
        }
        seq = kallsyms->private_data;
        if (!seq) {
                printk(KERN_WARNING "/proc/kallsyms: no private data\n");
                goto err_close;
        }
        *addr = NULL;
        for (iter = seq->op->start(seq, &pos); iter;
             iter = seq->op->next(seq, iter, &pos)) {
                if (!strcmp(iter->name, symbol))
                        *addr = (void *)iter->value;
	}
        if (*addr == NULL) {
                printk(KERN_WARNING "/proc/kallsyms: %s not found\n", symbol);
        } else {
                printk(KERN_INFO "/proc/kallsyms: %s has address = 0x%x\n",
                       symbol, (unsigned int)*addr);
                ret = 0;
        }
 err_close:
       filp_close(kallsyms, NULL);
 done:
       return ret;
}

#endif /* GET_SYMBOL */

static inline int
get_file_pos(int fd)
{
	int ret = 0;
	struct file *f;
	if ((f = fget(fd))) {
		struct inode *inode;

		if (f->f_flags & O_APPEND) { /* handle O_APPEND! */
			inode = f->f_dentry->d_inode;
			if (inode && !S_ISBLK(inode->i_mode))
				ret = inode->i_size;
		} else {
			ret = f->f_pos;
		}
		fput(f);
	}
	return ret;
}

#define SET_INODE_NR(inr, d, i, g, m) \
	(inr)->dev = d; \
	(inr)->inode = i; \
	(inr)->gen = g; \
	(inr)->type = m & S_IFMT

/* This function fills nd. path_release(nd) should be called by the caller */
static inline int
get_inode_path(const char *pathname,
               struct custat *iself, struct custat *iparent,
               char **canonpath, unsigned int canonpathlen)
{
	struct inode *inode;
	struct kstat stbuf;
        int res;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	struct path path;
#else
	struct nameidata nd;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	res = user_path(pathname, &path);
#else
        res = user_path_walk(pathname, &nd);
#endif
        if (res)
                goto out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	inode = path.dentry->d_inode;
#else
        inode = nd.path.dentry->d_inode;
#endif
	if (inode == NULL) {
		printad("%s(%s): NULL inode\n", __FUNCTION__, pathname);
		res = -EFAULT;
		goto out;
	}
        ASSERT_AUDIT(inode);
        if (iself) {
                iself->i_dev = GET_INODE_IDEV(inode);
                iself->i_ino = inode->i_ino;
                iself->i_igen = inode->i_generation;
                iself->i_mode = inode->i_mode;
                iself->i_nlink = inode->i_nlink;
                iself->i_uid = inode->i_uid;
                iself->i_gid = inode->i_gid;
		stbuf.size = 0;
		generic_fillattr(inode, &stbuf);	
		iself->i_size = stbuf.size;
        }

        if (iparent) {
                /* Upon obtaining the child's dentry the parent's dentry and
                 * the inode should always present. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
		inode = path.dentry->d_parent->d_inode;
#else
                inode = nd.path.dentry->d_parent->d_inode;
#endif
                ASSERT_AUDIT(inode);
                iparent->i_dev = GET_INODE_IDEV(inode);
                iparent->i_ino = inode->i_ino;
                iparent->i_igen = inode->i_generation;
                iparent->i_mode = inode->i_mode;
        }

        if (canonpath) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
                strncpy(*canonpath, (path.dentry->d_name).name,
                        canonpathlen - 1);
#else
                strncpy(*canonpath, (nd.path.dentry->d_name).name,
                        canonpathlen - 1);
#endif
                (*canonpath)[canonpathlen - 1] = '\0';
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	path_put(&path);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	path_put(&nd.path);
#else
	path_release(&nd);
#endif
#endif
out:
        return res;
}

/* This function fills nd. path_release(nd) should be called by the caller */
static inline int
get_inode_path_link(const char *pathname,
                    struct custat *iself, struct custat *iparent,
                    char **canonpath, unsigned int canonpathlen)
{
	struct inode *inode;
        int res = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	struct path path;
#else
	struct nameidata nd;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
        res = user_lpath(pathname, &path);
#else
        res = user_path_walk_link(pathname, &nd);
#endif
        if (res)
                goto out;

        /* Upon obtaining the dentry the inode should always present. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
        inode = path.dentry->d_inode;
#else
        inode = nd.path.dentry->d_inode;
#endif
        ASSERT_AUDIT(inode);
        if (iself) {
                iself->i_dev = GET_INODE_IDEV(inode);
                iself->i_ino = inode->i_ino;
                iself->i_igen = inode->i_generation;
                iself->i_mode = inode->i_mode;
                iself->i_nlink = inode->i_nlink;
                iself->i_uid = inode->i_uid;
                iself->i_gid = inode->i_gid;
        }

        if (iparent) {
                /* Upon obtaining the child's dentry the parent's dentry and
                 * the inode should always present. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
                inode = path.dentry->d_parent->d_inode;
#else
                inode = nd.path.dentry->d_parent->d_inode;
#endif
                ASSERT_AUDIT(inode);
                iparent->i_dev = GET_INODE_IDEV(inode);
                iparent->i_ino = inode->i_ino;
                iparent->i_igen = inode->i_generation;
                iparent->i_mode = inode->i_mode;
        }

        if (canonpath) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
                strncpy(*canonpath, (path.dentry->d_name).name,
#else
                strncpy(*canonpath, (nd.path.dentry->d_name).name,
#endif
                        canonpathlen - 1);
                (*canonpath)[canonpathlen - 1] = '\0';
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	path_put(&path);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	path_put(&nd.path);
#else
	path_release(&nd);
#endif
#endif
out:
        return res;
}


/* This function fills a file pointer. fput(f) should be called by the caller */
static int
get_inode_fd(struct file **f, int fd, struct custat *iself, 
             struct custat *iparent, char **canonpath,
             unsigned int canonpathlen, const struct timeval *time)
{
	struct inode *inode;
        int res = -ENOENT;

        *f = fget(fd);
        if (!(*f) || IS_ERR(*f)) {
                goto out;
        }

        /* Upon obtaining the file the dentry and the inode should always
         * present. */
        inode = (*f)->f_dentry->d_inode;
        ASSERT_AUDIT(inode);

        /* Override the generation number if it is supplied
         * from argument but not from inode.
         * This is used together with the inode number as the socket ID. */
        if (time && !(inode->i_generation)) {
                inode->i_generation = (__u32)time->tv_sec;
        }

        if (iself) {
                iself->i_dev = GET_INODE_IDEV(inode);
                iself->i_ino = inode->i_ino;
                iself->i_igen = inode->i_generation;
                iself->i_mode = inode->i_mode;
                iself->i_nlink = inode->i_nlink;
                iself->i_uid = inode->i_uid;
                iself->i_gid = inode->i_gid;
        }

        if (iparent) {
                /* Upon obtaining the child's dentry the parent's dentry and
                 * the inode should always present. */
                inode = (*f)->f_dentry->d_parent->d_inode;
                ASSERT_AUDIT(inode);
                iparent->i_dev = GET_INODE_IDEV(inode);
                iparent->i_ino = inode->i_ino;
                iparent->i_igen = inode->i_generation;
                iparent->i_mode = inode->i_mode;
        }

        if (canonpath) {
                strncpy(*canonpath, ((*f)->f_dentry->d_name).name,
                        canonpathlen - 1);
                (*canonpath)[canonpathlen - 1] = '\0';
        }
        res = 0;

out:
        return res;
}

#ifdef SOLITUDE

/* returns 0 on error */
static inline int
page_align(struct auditevent *e)
{
        EVENT_SIZE(page_align_class);
        e->size = event_size;
        printad("%s: starts\n", __FUNCTION__);
        /* e->size is read by PAGE_ALIGN_ALLOC and then set to the total
         * amount of space allocated for this event. */
        PAGE_ALIGN_ALLOC;
        if (e->size > PAGE_SIZE) { /* send alignment header */
                event.t_header.event_class = AUDIT_CLASS_ALIGN;
                event.t_header.event_size = event_size - sizeof(header_token);
                event.t_header.num_blocks = 1;
                event.skip_len = e->size - event_size - PAGE_SIZE;
                ASSERT_AUDIT(event.skip_len >= 0);
                event.t_header.data_size = event.skip_len;
                audit_write_event(&event, event_size, e);
                /* fakes aligned data write */
                e->size -= PAGE_SIZE - e->offset;
                e->offset = PAGE_SIZE;
                ASSERT_AUDIT(e->size == PAGE_SIZE); // added by shvet
        }
        return 1;
 bail:
        return 0;
}

static inline void
send_original_file(struct file *in_file, int file_len, struct inode_nr inr)
{
        struct auditevent e;
        EVENT_SIZE(snapshot_class);
        static int init_start_time = -1;
        snapshot_class *sc;
        DECLARE_WAIT_QUEUE_HEAD(snapshot_queue); /* queue woken by sendfile */
        
        ASSERT_AUDIT(in_file);
        if (init_start_time < 0) {
                init_start_time = get_process_start_time(1);
        }
        printas("send_original_file: start\n");
        if (!page_align(&e)) { /* align page */
                return;
        }
        event.t_header.event_class = AUDIT_CLASS_SNAPSHOT;
        event.skip_len = PAGE_SIZE - event_size;
        event.file_len = file_len;
        event.i_nr = inr;
        event.in_file = in_file;
        event.wq = (void*)&snapshot_queue;
        
        /*printas("file 0x%x, file_len %d skip_len %d\n",
               (unsigned int)event.in_file, 
               event.file_len, event.skip_len);
        */
        AUDIT_GENERIC(2, event.skip_len + event.file_len);

        /* fake PID */
        event.t_header.pid = 1;
//        event.t_header.pid_time = init_start_time;
        ASSERT_AUDIT(e.offset == PAGE_SIZE);
        WRITE_EVENT;
        /* fakes aligned data write */
        e.size = 0;
        e.offset = PAGE_SIZE; /* not needed */
        e.node->marker_flag = 1;
        sc = (snapshot_class *)page_address(e.node->page);

        /* blocks until snapshot is sent */
        atomic_inc(&auditdata.sendfile_active);
        SEND_DATA;
        printad("send_original_file: block\n");
	wait_event(snapshot_queue, !e.node->marker_flag);
	atomic_dec(&auditdata.sendfile_active);
        printad("send_original_file: end\n");
}

static int
do_snapshot_sendfile(snapshot_class* sc)
{
        loff_t pos = 0;
        int ret; 
        mode_t old_mode;
        int in_fd;

        printad("%s: starts\n", __FUNCTION__);

        if ((in_fd = get_unused_fd()) < 0) {
                printas("%s: get_unused_fd: error = %d\n", 
                       __FUNCTION__, in_fd);
                return in_fd;
        }
        ASSERT_AUDIT(sc->in_file);
        fd_install(in_fd, sc->in_file);
        
        old_mode = sc->in_file->f_mode;
        /* In case the file does not have read permissions then provide it
         * read permission*/
        sc->in_file->f_mode |= 1;

        ret = (do_sendfile_fn)(auditdata.fd, in_fd, &pos, sc->file_len, 0);
        if (ret < 0) {
                printas("%s: Failed to do sendfile: err = %d\n",
                       __FUNCTION__, ret);
        }
        sc->in_file->f_mode = old_mode;
        audit_fd_close(in_fd, sc->in_file);
        printad("%s: end\n", __FUNCTION__);
        if (ret >= 0 && ret < sc->file_len) {
                /* TODO: should send padding. fake an error at the moment */
                ret = -ENETRESET;
        }
        return ret;
}

/* fake system call, not asmlinkage */
static int
solitude_commit(unsigned long user_data)
{
        struct auditevent e;
        EVENT_SIZE(commit_class);

        if (copy_from_user(&event.args, (void *)user_data, sizeof(event.args)))
                return -EFAULT;

        /* make sure that the char array ends in 0 */
        event.args.solitude_name[SOLITUDE_NAME_MAX_LEN - 1] = 0;
        
        /* process should not be an ifs process */
        if (process_in_ifs())
                return -EINVAL;

        /* taint process */
        current->flags |= TAINTED_PROCESS_MASK;
        
        /* audit and send data */
        event.t_header.event_class = AUDIT_CLASS_COMMIT;
        event.t_header.event_id = 0; /* fake call */
        event.t_header.ret = 0;
        AUDIT_GENERIC(0, 0);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
        return 0;
}
#endif /* SOLITUDE */

/***
 *** Section 7: system calls we are auditing
 ***/
/*
 * Note that strnlen_user() returns the length of a string including the
 * NUL terminating character while strnlen() returns the length of a string
 * without the NUL terminating character! In both cases, we add space for a
 * NUL terminating character.
 *
 */

static asmlinkage int
audit_kill(pid_t pid, int sig)
{
        int returncode;
        struct auditevent e;
        EVENT_SIZE(signal_class);

        returncode = orig_kill(pid, sig);
	if (!audit_process())
		goto bail;
        if (returncode < 0)
                goto bail;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_SIGNAL;
        event.t_header.event_id = __NR_kill;
        event.t_pid = pid;
//        event.t_pid_time = 0;
 //       if (pid > 0) {
//                int start_time = get_process_start_time(pid);
//                if (start_time > 0)
 //                       event.t_pid_time = start_time;
  //      }
        event.sig = sig;
        event.status = 0;
        event.options = 0;
        AUDIT_GENERIC(0, 0);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
        return returncode;
}

static inline int
do_audit_fork(int returncode, int syscall, int clone_flags,
              const struct timeval *fork_time)
{
        struct auditevent e;
        EVENT_SIZE(fork_class);
        PWD_SIZE;

#ifdef SOLITUDE
        if (process_in_ifs()) {
                ifs_fork(returncode);
                return 0;
        }
        if (!process_is_tainted())
                return 0;
#endif /* SOLITUDE */

        event.child_pid_time = get_process_start_time(returncode);
        if (event.child_pid_time < 0)
                event.child_pid_time = 0;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_FORK;
        event.t_header.event_id = syscall;
        event.clone_flags = clone_flags;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
	event.user_id = current_cred()->uid;
	event.group_id = current_cred()->gid;
	event.euser_id = current_cred()->euid;
	event.egroup_id = current_cred()->egid;
#else
	event.user_id = current->uid;
	event.group_id = current->gid;
	event.euser_id = current->euid;
	event.egroup_id = current->egid;
#endif
        strncpy(event.comm, current->comm, 16);
        event.comm[16-1] = 0;
        ((header_token *)&event)->time.tv_sec = fork_time->tv_sec;
        ((header_token *)&event)->time.tv_usec = fork_time->tv_usec;
        AUDIT_GENERIC_WOTIME(1, event.pwd_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_PWD;
        SEND_DATA;
        return 0;
 bail:
        return 1;
}

static asmlinkage int
audit_fork(struct pt_regs regs)
{
        int returncode;
        int clone_flags;
        int syscall = __NR_fork;
        struct timeval time_temp;

	printad("%s\n", __FUNCTION__);
	if (!audit_process())
		return orig_fork(regs);
        do_gettimeofday(&time_temp);

        clone_flags = SIGCHLD;
        returncode = orig_fork(regs);
	if (returncode < 0)
		goto bail;
        if (returncode >= 0) { /* log at the parent */
                do_audit_fork(returncode, syscall, clone_flags, &time_temp);
        }
bail:
        return returncode;
}

static asmlinkage int
audit_vfork(struct pt_regs regs)
{
        int returncode;
        int clone_flags;
        int syscall = __NR_vfork;
        struct timeval time_temp;

	printad("%s\n", __FUNCTION__);
	if (!audit_process())
		return orig_vfork(regs);
        do_gettimeofday(&time_temp);

        clone_flags = CLONE_VFORK | CLONE_VM | SIGCHLD;
        returncode = orig_vfork(regs);
	if (returncode < 0)
		goto bail;
        if (returncode >= 0) {
                do_audit_fork(returncode, syscall, clone_flags, &time_temp);
        }
bail:
        return returncode;
}

static asmlinkage int
audit_clone(struct pt_regs regs)
{
        int returncode;
        int clone_flags;
        int syscall = __NR_clone;
        struct timeval time_temp;

	printad("%s\n", __FUNCTION__);
	if (!audit_process())
		return orig_clone(regs);
        do_gettimeofday(&time_temp);

#ifndef CLONE_IDLETASK
#define CLONE_IDLETASK 0
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
        clone_flags = regs.bx & ~CLONE_IDLETASK;
#else
        clone_flags = regs.ebx & ~CLONE_IDLETASK;
#endif
        returncode = orig_clone(regs);
        if (returncode >= 0) {
                do_audit_fork(returncode, syscall, clone_flags, &time_temp);
        }
        return returncode;
}

/* "cmd" and "arg" parameters are meaningful for fcntl only */
static inline int
do_audit_dup(int returncode, int oldfd, int newfd, int cmd, int arg,
             int syscall)
{
        struct auditevent e;
        struct file* f = NULL;
        DECLARE_INODE(iself);
        EVENT_SIZE(dup_class);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);

        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_DUP;
        event.t_header.event_id = syscall;
        event.fd = oldfd;
        event.new_fd = newfd;
        event.cmd = cmd;
        event.arg = arg;
        if (!get_inode_fd(&f, oldfd, &iself, NULL, NULL, 0, NULL)) {
                SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                             iself.i_igen, iself.i_mode);
                fput(f);
        }
        
        AUDIT_GENERIC(0, 0);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
        return 0;
 bail:
        return 1;
}

static asmlinkage int
audit_dup(int oldfd)
{
        int returncode;
        returncode = orig_dup(oldfd);
	if (!audit_process())
		goto bail;
        if (returncode >= 0)
                do_audit_dup(returncode, oldfd, returncode, 0, 0, __NR_dup);
bail:
        return returncode;
}

static asmlinkage int
audit_dup2(int oldfd, int newfd)
{
        int returncode;
        returncode = orig_dup2(oldfd, newfd);
	if (!audit_process())
		goto bail;
        if (returncode >= 0)
                do_audit_dup(returncode, oldfd, newfd, 0, 0, __NR_dup2);
bail:
        return returncode;
}

static asmlinkage int
audit_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
        int returncode;
        returncode = orig_fcntl(fd, cmd, arg);
	if (!audit_process())
		goto bail;
        if (returncode >= 0)
                do_audit_dup(returncode, fd, returncode, cmd, arg, __NR_fcntl);
bail:
        return returncode;
}

static asmlinkage int
audit_fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg)
{
        int returncode;
        returncode = orig_fcntl64(fd, cmd, arg);
	if (!audit_process())
		goto bail;
        if (returncode >= 0)
                do_audit_dup(returncode, fd, returncode, cmd, arg,
                             __NR_fcntl64);
 bail:
        return returncode;
}
        
static asmlinkage int
audit_close(int fd)
{
        int returncode;
        struct auditevent e;
#ifdef VERSIONING
        struct file* f = NULL;
        DECLARE_INODE(iself);
#ifdef VERSIONING_SNAPSHOT
	char fullpath[MAX_PATH];
	char *vsnapshot_path = NULL;
	u32 vsnapshot;
	mm_segment_t fs;
#endif /* VERSIONING_SNAPSHOT */
#endif /* VERSIONING */

//        DECLARE_INODE(iparent);
        EVENT_SIZE(close_class);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
	if (!audit_process())
		return orig_close(fd);
#ifdef VERSIONING
        if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
                SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                        iself.i_igen, iself.i_mode);
                fput(f);
	}
#endif

#ifdef LOG_STAT
        if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
		if (!get_name_from_node(iself.i_dev, iself.i_ino, iself.i_igen, fullpath, sizeof(fullpath), NULL)) {
			fs = get_fs();
			set_fs(get_ds());
    			log_stat(fullpath, time(), 0, 0, "C");
			set_fs(fs);	
		}
		fput(f);
	}
#endif
        returncode = orig_close(fd);
        if (returncode < 0)
                goto bail;
#ifdef VERSIONING
#ifdef VERSIONING_SNAPSHOT
	if (!get_name_from_node(iself.i_dev, iself.i_ino, iself.i_igen,  fullpath, sizeof(fullpath), &vsnapshot)) {
		remove_node(iself.i_dev, iself.i_ino, iself.i_igen);
		if (vsnapshot) {
			vsnapshot_path = kmalloc(MAX_PATH, GFP_KERNEL);
			if (vsnapshot_path != NULL) {
				snprintf(vsnapshot_path, MAX_PATH, "%s.%u%s", fullpath, vsnapshot, VERSIONMODIFIER);
				if (!compare_file(fullpath, vsnapshot_path))
					update_version_from_snapshot(fullpath, vsnapshot_path);
				fs = get_fs();
				set_fs(KERNEL_DS);
				orig_unlink(vsnapshot_path);
				set_fs(fs);
				kfree(vsnapshot_path);
			} else
				printk("%s: allocate snapshot path failed\n", __FUNCTION__);
		}
	}
#else /* VERSIONING_SNAPSHOT */
	remove_node(iself.i_dev, iself.i_ino, iself.i_igen);
#endif /* VERSIONING SNAPSHOT */
#endif /* VERSIONING */
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CLOSE;
        event.t_header.event_id = __NR_close;
        event.fd = fd;
        AUDIT_GENERIC(0, 0);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
        return returncode;
}

static inline int
do_audit_read1(int returncode, int fd, size_t count, loff_t pos, int flags,
               int syscall, struct inode_nr *inr, struct timeval *time)
{
        struct auditevent e;
        EVENT_SIZE(read1_class);
        SET_INODE_NR(&(event.i_nr), inr->dev, inr->inode,
                inr->gen, inr->type);

        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_READ1;
        event.t_header.event_id = syscall;
        event.fd = fd;
	event.pos = pos;
        event.len = count;
//        event.flags = flags;
//        event.data_len = 0;
        if (time) {
                ((header_token *)&event)->time.tv_sec = time->tv_sec;
                ((header_token *)&event)->time.tv_usec = time->tv_usec;
                AUDIT_GENERIC_WOTIME(1, 0);
        } else {
                AUDIT_GENERIC(1, 0);
        }
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
	return 0;
 bail:
        return 1;
}

static inline int
do_audit_read2(int returncode, int fd, size_t count, int call, int flags,
               unsigned int ip, unsigned short port, int syscall,
               struct inode_nr *inr, struct timeval *time)
{
        struct auditevent e;
        EVENT_SIZE(read2_class);
        SET_INODE_NR(&(event.i_nr), inr->dev, inr->inode,
                inr->gen, inr->type);

        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_READ2;
        event.t_header.event_id = syscall;
        event.fd = fd;
        event.call = call;
        event.udp_ip = ip;
        event.udp_port = port;
        event.len = count;
//        event.flags = flags;
        event.isaccept = (inr->gen & ISACCEPT_MASK)? 1:0;
        event.i_nr.gen &= ~ISACCEPT_MASK;
        event.data_len = 0;
        if (time) {
                ((header_token *)&event)->time.tv_sec = time->tv_sec;
                ((header_token *)&event)->time.tv_usec = time->tv_usec;
                AUDIT_GENERIC_WOTIME(1, event.data_len);
        } else {
                AUDIT_GENERIC(1, event.data_len);
        }
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
	return 0;
 bail:
        return 1;
}

static inline int
do_audit_read2_stream(int returncode, int fd, size_t count, int call, int flags,
                      int syscall, struct inode_nr *inr, struct timeval *time)
{
        int err;
        unsigned int ip;
        unsigned short port;
        struct socket *sock;

        ip = 0;
        port = 0;
        sock = sockfd_lookup(fd, &err);
        if (sock && sock->sk && inet_sk(sock->sk)) {
                ip = ntohl(inet_sk(sock->sk)->daddr);
                port = ntohs(inet_sk(sock->sk)->dport);
                sockfd_put(sock);
        }
        return do_audit_read2(returncode, fd, count, SYS_RECV,
                flags, ip, port, syscall, inr, time);
}


static inline int
do_audit_read(int returncode, int fd, size_t count, loff_t pos, int flags,
              int syscall, struct timeval *time)
{
        struct inode_nr inr;
        struct file* f = NULL;
        DECLARE_INODE(iself);

        if (get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
                return 1;
        }
        SET_INODE_NR(&inr, iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
#ifdef SOLITUDE
        if (process_in_ifs() || 
            process_tainted_by_file_f(f) == 0) {
                fput(f);
                return 0;
        }
        // For socket calls need to decide what should be done
#endif /* SOLITUDE */
        fput(f);

        switch (inr.type) {
        case S_IFIFO:
        case S_IFSOCK:
//                return do_audit_read2_stream(returncode, fd, count,
 //                       SYS_SEND, flags, syscall, &inr, time);
		return 0;
        default:
                return do_audit_read1(returncode, fd, count, pos,
                        flags, syscall, &inr, time);
        }
}

static inline int
do_audit_write1(int returncode, int fd, const struct iovec *iov, size_t count,
	        loff_t pos, int flags, int syscall, struct inode_nr *inr,
                struct timeval *time)
{
        struct auditevent e;
	size_t i;
#ifdef SAVE_WRITE_DATA
        size_t len, size;
#endif
        EVENT_SIZE(write1_class);
        SET_INODE_NR(&(event.i_nr), inr->dev, inr->inode, inr->gen, inr->type);

        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_WRITE1;
        event.t_header.event_id = syscall;
        event.fd = fd;
	event.pos = pos;
        event.len = 0;
        for (i = 0; i < count; i++) {
                event.len += iov[i].iov_len;
        }
//        event.flags = flags;
        event.data_len = 0; /* amount of data to monitor */
#ifdef SAVE_WRITE_DATA
        /* If a write has a positive return code, iov[0] must exist.
         * However, iov[0].iov_base is null for sendfile operation,
         * so check and not to deliver the user data buffer.
         */
        if (returncode > 0 && iov[0].iov_base) {
                if (auditdata.rw_type == AUDIT_RW_INF) {
                        event.data_len = returncode;
                } else if (auditdata.rw_type == AUDIT_RW_SET) {
                        event.data_len = min_t(int, AUDIT_RW_LENGTH,
					       returncode);
                }
        }
#endif
        if (time) {
                ((header_token *)&event)->time.tv_sec = time->tv_sec;
                ((header_token *)&event)->time.tv_usec = time->tv_usec;
#ifdef SAVE_WRITE_DATA
                AUDIT_GENERIC_WOTIME(1, event.data_len);
#else
                AUDIT_GENERIC_WOTIME(1, 0);
#endif
        } else {
#ifdef SAVE_WRITE_DATA
                AUDIT_GENERIC(1, event.data_len);
#else
                AUDIT_GENERIC(1, 0);
#endif
        }
        AUDIT_ALLOC;
        WRITE_EVENT;
#ifdef SAVE_WRITE_DATA
        i = 0;
        len = event.data_len;
        while (len > 0) { /* copy the data from user space */
                size = min_t(size_t, len, iov[i].iov_len);
		if (size == 0)
			break;
                if (iov[i].iov_base)
                        audit_write_user_event(iov[i++].iov_base, size, &e);
                len -= size;
        }
#endif
        SEND_DATA;
	return 0;
 bail:
        return 1;
}

#ifdef CONFIG_AUDIT_MMAP
/* we have to make our own version of this function which doesn't use 
 * "current->pid" as the real pid, since we sometimes audit a page write 
 * in the context of a process that didn't actually invoke the i/o */

static inline int
do_audit_write1_changewriter(int returncode, int fd, const struct iovec *iov, size_t count,
                loff_t pos, int flags, int syscall, struct inode_nr *inr,
                struct timeval *time, struct task_struct* writer)
{
        struct auditevent e;
        size_t i, len, size;
        EVENT_SIZE(write1_class);
        SET_INODE_NR(&(event.i_nr), inr->dev, inr->inode, inr->gen, inr->type);

        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_WRITE1;
        event.t_header.event_id = syscall;
        event.fd = fd;
        event.pos = pos;
        event.len = 0;
        for (i = 0; i < count; i++) {
                event.len += iov[i].iov_len;
        }
//        event.flags = flags;
        event.data_len = 0; /* amount of data to monitor */
        /* If a write has a positive return code, iov[0] must exist.
         * However, iov[0].iov_base is null for sendfile operation,
         * so check and not to deliver the user data buffer.
         */

        if (returncode > 0 && iov[0].iov_base) {
                if (auditdata.rw_type == AUDIT_RW_INF) {
                        event.data_len = returncode;
                } else if (auditdata.rw_type == AUDIT_RW_SET) {
                        event.data_len = min_t(int, AUDIT_RW_LENGTH,
                                               returncode);
                }
        }
        if (time) {
                ((header_token *)&event)->time.tv_sec = time->tv_sec;
                ((header_token *)&event)->time.tv_usec = time->tv_usec;
                AUDIT_GENERIC_WOTIME(1, event.data_len);
        } else {
                AUDIT_GENERIC(1, event.data_len);
        }

	/* overwrite pid written by AUDIT_GENERIC, which assumes
	 * "current" is the writer */
	event.t_header.pid=writer->pid;

        AUDIT_ALLOC;
        WRITE_EVENT;
        i = 0;
        len = event.data_len;
        while (len > 0) { /* copy the data from _kernel_ space */
                size = min_t(size_t, len, iov[i].iov_len);
                if (iov[i].iov_base) {
                        audit_write_event(iov[i++].iov_base, size, &e);
		}
                len -= size;
        }
        SEND_DATA;
        return 0;
 bail:
        return 1;
}

void audit_mmap_write_partial_ocasta(struct page* page, struct task_struct* writer, int offset, int bytes, int from)
{
	struct inode* inp = page->mapping->host;
	loff_t pos = ((page->index)*4096)+offset;
	/* int size = inp->i_size; */
	/* size_t count = (size >= (pos+4096))?4096:(size-pos); */
	int returncode = bytes; /* bytes written */
	int fd = -from; 	/* we don't have an fd */ 
	int flags = 0;      	/* what should this be set to? */
	int syscall = 4; 	/* we'll pretend it's a "write" for now */
	struct inode_nr inr;
        struct timeval* time = NULL;
	struct iovec iov;

	if (unlikely(bytes < 0 || offset < 0 || offset+bytes > 4096))
	{
		printk(KERN_DEBUG 
                       "audit_mmap_write_partial_ocasta: bad write\n");
		return;
	}

	iov.iov_base = ((unsigned char *)page_address(page))+offset;
	iov.iov_len  = bytes;

	SET_INODE_NR(&inr, 
		GET_INODE_IDEV(inp), /* inp->i_rdev, */
		do_audit_write1_changewriter(returncode, fd, &iov, 1 /*count*/, pos, 
			flags, syscall, &inr, time, writer);
}

void audit_mmap_read_partial_ocasta(struct page* page, struct task_struct* writer, int offset, int bytes, int from) {

	struct inode* inp = page->mapping->host;
        loff_t pos = ((page->index)*4096)+offset;
        /* int size = inp->i_size; */
        /* size_t count = (size >= (pos+4096))?4096:(size-pos); */
        int returncode = bytes; /* bytes written */
        int fd = -from;         /* we don't have an fd */
        int flags = 0;          /* what should this be set to? */
        int syscall = 3;        /* we'll pretend it's a plain "read" for now */
        struct inode_nr inr;
        struct timeval* time = NULL;

        if (unlikely(bytes < 0 || offset < 0 || offset+bytes > 4096))
        {
                printk(KERN_DEBUG 
			"audit_mmap_write_partial_ocasta: bad write\n");
                return;
        }

	SET_INODE_NR(&inr,
                GET_INODE_IDEV(inp), /* inp->i_rdev, */
                inp->i_ino,
                inp->i_generation,
                inp->i_mode);

	do_audit_read1(returncode, fd, bytes, pos,
                        flags, syscall, &inr, time);
}
#endif

static inline int
do_audit_write2(int returncode, int fd, const struct iovec *iov, size_t count,
	        int call, int flags, unsigned int ip, unsigned short port,
                int syscall, struct inode_nr *inr, struct timeval *time)
{
        struct auditevent e;
        size_t i;
        EVENT_SIZE(write2_class);
        SET_INODE_NR(&(event.i_nr), inr->dev, inr->inode, inr->gen, inr->type);

        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_WRITE2;
        event.t_header.event_id = syscall;
        event.fd = fd;
	event.call = call;
        event.udp_ip = ip;
        event.udp_port = port;
        event.len = 0;
        for (i = 0; i < count; i++) {
                event.len += iov[i].iov_len;
        }
//        event.flags = flags;
        event.isaccept = (inr->gen & ISACCEPT_MASK)? 1:0;
        event.i_nr.gen &= ~ISACCEPT_MASK;
        event.data_len = 0; /* amount of data to monitor */
        if (time) {
                ((header_token *)&event)->time.tv_sec = time->tv_sec;
                ((header_token *)&event)->time.tv_usec = time->tv_usec;
#ifdef SAVE_WRITE_DATA
                AUDIT_GENERIC_WOTIME(1, event.data_len);
#else
                AUDIT_GENERIC_WOTIME(1, 0);
#endif
        } else {
#ifdef SAVE_WRITE_DATA
                AUDIT_GENERIC(1, event.data_len);
#else
                AUDIT_GENERIC(1, 0);
#endif
        }
        AUDIT_ALLOC;
        WRITE_EVENT;
        i = 0;
        SEND_DATA;
	return 0;
 bail:
        return 1;
}

static inline int
do_audit_write2_stream(int returncode, int fd, const struct iovec *buf,
                       size_t count, int call, int flags, int syscall,
                       struct inode_nr *inr, struct timeval *time)
{
        int err;
        unsigned int ip;
        unsigned short port;
        struct socket *sock;

        ip = 0;
        port = 0;
        sock = sockfd_lookup(fd, &err);
        if (sock && sock->sk && inet_sk(sock->sk)) {
                ip = ntohl(inet_sk(sock->sk)->daddr);
                port = ntohs(inet_sk(sock->sk)->dport);
                sockfd_put(sock);
        }
        return do_audit_write2(returncode, fd, buf, count, SYS_SEND,
                flags, ip, port, syscall, inr, time);
}

static inline int
do_audit_write(int returncode, int fd, const struct iovec *buf, size_t count,
	       loff_t pos, int flags, int syscall, struct timeval *time)
{
        struct inode_nr inr;
        struct file* f = NULL;
        DECLARE_INODE(iself);
        SET_INODE_NR_SETSB(&inr, 0, 0, 0, 0, iself);

        if (get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
                return 1;
        }
        SET_INODE_NR(&inr, iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
#ifdef SOLITUDE
        if (process_in_ifs() || file_tainted_by_process_f(f, &inr, 1) == 0) {
                fput(f);
                return 0;
        }
#endif /* SOLITUDE */
        fput(f);
        switch (inr.type) {
        case S_IFIFO:
        case S_IFSOCK:
//                return do_audit_write2_stream(returncode, fd, buf, count,
 //                       SYS_SEND, flags, syscall, &inr, time);
		return 0;
        default:
                return do_audit_write1(returncode, fd, buf, count, pos,
                        flags, syscall, &inr, time);
        }
}

static asmlinkage ssize_t
audit_read(int fd, void *buf, size_t count)
{
	loff_t opos;
	int returncode;
#ifdef LOG_STAT
	char fullpath[MAX_PATH];
	struct file *f = NULL;
        DECLARE_INODE(iself);
        mm_segment_t fs;
#endif

	if (!audit_process()) {
		returncode = orig_read(fd, buf, count);
		goto out;
	}
	opos = get_file_pos(fd);
        returncode = orig_read(fd, buf, count);

#ifdef LOG_STAT
       	if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
		if (!get_name_from_node(iself.i_dev, iself.i_ino, iself.i_igen, fullpath, sizeof(fullpath), NULL)) {
			fs = get_fs();
			set_fs(get_ds());
    			log_stat(fullpath, time(), opos, returncode, "R");
			set_fs(fs);	
		}
		fput(f);
	}
#endif
        if (returncode >= 0)
                do_audit_read(returncode, fd, count, opos, 0, __NR_read, NULL);
out:
	return returncode;
}

static asmlinkage ssize_t
audit_write(int fd, const void __user *buf, size_t count)
{
        struct iovec iov;
#if defined(VERSIONING) || defined(LOG_STAT)
	char fullpath[MAX_PATH];
	struct file *f = NULL;
        DECLARE_INODE(iself);
        mm_segment_t fs;
#endif
	loff_t opos;
	int returncode;
	if (!audit_process())
		return orig_write(fd, (void *)buf, count);

#ifdef VERSIONING
       	if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
		fullpath[0] = '\0';
#ifndef VERSIONING_SNAPSHOT
		if (!get_name_from_node(iself.i_dev, iself.i_ino, iself.i_igen, fullpath, sizeof(fullpath), NULL)) {
			//printk("%s: pid(%d) write %s\n", __FUNCTION__, current->pid, fullpath);
			update_version(fullpath, count, opos, 0, "WV");
		}
#endif /* VERSIONING_SNAPSHOT */
                fput(f);
        }
#endif /* VERSIONING */

	opos = get_file_pos(fd);
        returncode = orig_write(fd, (void *)buf, count);

#ifdef LOG_STAT
       	if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
		if (!get_name_from_node(iself.i_dev, iself.i_ino, iself.i_igen, fullpath, sizeof(fullpath), NULL)) {
			fs = get_fs();
			set_fs(get_ds());
    			log_stat(fullpath, time(), opos, returncode, "W");
			set_fs(fs);
		}
                fput(f);
	}
#endif
        iov.iov_base = (void *)buf;
	iov.iov_len = count;
        if (returncode >= 0)
                do_audit_write(returncode, fd, &iov, 1, opos, 0, __NR_write,
                               NULL);
	return returncode;
}

static asmlinkage ssize_t
audit_pread(int fd, void *buf, size_t count, loff_t pos)
{
	loff_t opos = pos;
#if defined(LOG_STAT)
	char fullpath[MAX_PATH];
	struct file *f = NULL;
        DECLARE_INODE(iself);
        mm_segment_t fs;
#endif
        int returncode = orig_pread(fd, buf, count, pos);

#ifdef LOG_STAT
       	if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
		if (!get_name_from_node(iself.i_dev, iself.i_ino, iself.i_igen, fullpath, sizeof(fullpath), NULL)) {
			fs = get_fs();
			set_fs(get_ds());
    			log_stat(fullpath, time(), pos, returncode, "R2");
			set_fs(fs);
		}
		fput(f);
	}
#endif
	if (!audit_process())
		return returncode;
        if (returncode >= 0)
                do_audit_read(returncode, fd, count, opos, 0, __NR_pread, NULL);
	return returncode;
}

static asmlinkage ssize_t
audit_pwrite(int fd, const void *buf, size_t count, loff_t pos)
{
        struct iovec iov;
	loff_t opos = pos;
#if defined(LOG_STAT)
	char fullpath[MAX_PATH];
	struct file *f = NULL;
        DECLARE_INODE(iself);
        mm_segment_t fs;
#endif
        int returncode = orig_pwrite(fd, (void *)buf, count, pos);

#ifdef LOG_STAT
       	if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
		if (!get_name_from_node(iself.i_dev, iself.i_ino, iself.i_igen, fullpath, sizeof(fullpath), NULL)) {
			fs = get_fs();
			set_fs(get_ds());
    			log_stat(fullpath, time(), pos, returncode, "W2");
			set_fs(fs);
		}
		fput(f);
	}
#endif
	if (!audit_process())
		return returncode;
        iov.iov_base = (void *)buf;
        iov.iov_len = count;
        if (returncode >= 0)
                do_audit_write(returncode, fd, &iov, 1, opos, 0, __NR_pwrite, 
                               NULL);
	return returncode;
}

static asmlinkage ssize_t
audit_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
        int returncode;
        struct timeval time;
        struct iovec iov;
        off_t ipos;
	loff_t opos = get_file_pos(out_fd);
	if (!audit_process())
		return orig_sendfile(out_fd, in_fd, offset, count);
        do_gettimeofday(&time);

        ipos = 0;

        if (copy_from_user(&ipos, offset, sizeof(off_t))) {
                ipos = 0;
        }
        returncode = orig_sendfile(out_fd, in_fd, offset, count);
        if (returncode < 0)
                return returncode;
        iov.iov_base = NULL;
        iov.iov_len = count;
        do_audit_write(returncode, out_fd, &iov, 1, opos, 0, __NR_sendfile,
                &time);
        do_audit_read(returncode, in_fd, count, ipos, 0, __NR_sendfile, &time);
        return returncode;
}

static asmlinkage ssize_t
audit_readv(unsigned long fd, const struct iovec *vector, int count)
{
        struct iovec *iov;
	loff_t opos = get_file_pos(fd);
#if defined(LOG_STAT)
	char fullpath[MAX_PATH];
	struct file *f = NULL;
        DECLARE_INODE(iself);
        mm_segment_t fs;
#endif
        int i;
        ssize_t len;
        ssize_t returncode = orig_readv(fd, vector, count);

#ifdef LOG_STAT
       	if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
		if (!get_name_from_node(iself.i_dev, iself.i_ino, iself.i_igen, fullpath, sizeof(fullpath), NULL)) {
			fs = get_fs();
			set_fs(get_ds());
    			log_stat(fullpath, time(), opos, returncode, "R1");
			set_fs(fs);
		}
		fput(f);
	}
#endif
	if (!audit_process())
		goto bail;
        if (returncode < 0)
                return returncode;
        len = returncode;
        /* Try to get an accurate measurement of the length of the user data
         * supplied; otherwise just use the returncode.
         */
        iov = kmalloc(count * sizeof(struct iovec), GFP_KERNEL);
        if (iov) {
                if (!copy_from_user(iov, vector,
                        count * sizeof(struct iovec))) {
                        len = 0;
                        for (i = 0; i < count; i++) {
                                len += iov[i].iov_len;
                        }
                }
                kfree(iov);
        }
        do_audit_read(returncode, fd, len, opos, 0, __NR_readv, NULL);
bail:
        return returncode;
}

static asmlinkage ssize_t
audit_writev(unsigned long fd, const struct iovec *vector, int count)
{
        struct iovec *iov;
#if defined(LOG_STAT)
	char fullpath[MAX_PATH];
	struct file *f = NULL;
        DECLARE_INODE(iself);
        mm_segment_t fs;
#endif
	loff_t opos = get_file_pos(fd);
        ssize_t returncode = orig_writev(fd, vector, count);

#ifdef LOG_STAT
       	if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
		if (!get_name_from_node(iself.i_dev, iself.i_ino, iself.i_igen, fullpath, sizeof(fullpath), NULL)) {
			fs = get_fs();
			set_fs(get_ds());
    			log_stat(fullpath, time(), opos, returncode, "W1");
			set_fs(fs);
		}
		fput(f);
	}
#endif
	if (!audit_process()) {
		goto bail;
	}
        if (returncode < 0)
                return returncode;
        iov = kmalloc(count * sizeof(struct iovec), GFP_KERNEL);
        if (iov) {
                if (!copy_from_user(iov, vector,
                        count * sizeof(struct iovec))) {
                        do_audit_write(returncode, fd, iov, count, opos, 0,
                                       __NR_writev, NULL);
                }
                kfree(iov);
        }
bail:
        return returncode;
}

static inline void
audit_opentrunc(struct file *f, int fd, struct inode_nr *i_nr, 
                struct timeval *time)
{
        struct auditevent e;
        EVENT_SIZE(write1_class);
#ifdef SOLITUDE
        if (f && !process_in_ifs()) {
                /* audit call even if process is not tainted */
                // CHECK doesnt seem right (not a namespace operation) ?
                file_tainted_by_process_f(f, i_nr, 1);
        }
#endif /* SOLITUDE */
        SET_INODE_NR(&(event.i_nr), i_nr->dev, i_nr->inode, i_nr->gen,
                     i_nr->type);

        ((header_token *)&event)->time.tv_sec = time->tv_sec;
        ((header_token *)&event)->time.tv_usec = time->tv_usec;
        event.t_header.ret = 0;
        event.t_header.event_class = AUDIT_CLASS_WRITE1;
        event.t_header.event_id = __NR_ftruncate;
        event.fd = fd;
        event.len = 0;
        event.data_len = event.pos = 0;
	event.flags = 0;
        AUDIT_GENERIC_WOTIME(1, event.data_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
        return;
}

static asmlinkage long
audit_stat(const char *path, struct stat *buf)
{
	int returncode;
        struct auditevent e;
	char fullpath[MAX_PATH];
	char pathname[MAX_PATH];

        EVENT_SIZE(stat_class);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
	if (!audit_process())
		return orig_stat(path, buf);
#ifdef ACCESS_REDIRECT
	access_redirection(path, pathname, sizeof(pathname));
	parse_versioning_path(pathname, fullpath);
#else
	if (copy_from_user(pathname, path, strnlen_user(path, MAX_PATH)))
		return -EFAULT;
	get_fullpath(fullpath, pathname, sizeof(fullpath));
#endif
	returncode = orig_stat(path, buf);

        FULLPATH_SIZE;
        do_gettimeofday(&(((header_token *)&event)->time));
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_STAT;
        event.t_header.event_id = __NR_stat;
        AUDIT_GENERIC_WOTIME(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_FULLPATH;
        SEND_DATA;
 bail:
	return returncode;
}

static asmlinkage long
audit_stat64(const char *path, struct stat64 *buf)
{
	int returncode;
        struct auditevent e;
	char fullpath[MAX_PATH];
	char pathname[MAX_PATH];

        EVENT_SIZE(stat_class);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
	if (!audit_process())
		return orig_stat64(path, buf);
#ifdef ACCESS_REDIRECT
	access_redirection(path, pathname, sizeof(pathname));
	parse_versioning_path(pathname, fullpath);
#else
	if (copy_from_user(pathname, path, strnlen_user(path, MAX_PATH)))
		return -EFAULT;
	get_fullpath(fullpath, pathname, sizeof(fullpath));
#endif
	returncode = orig_stat64(path, buf);

        FULLPATH_SIZE;
        do_gettimeofday(&(((header_token *)&event)->time));
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_STAT;
        event.t_header.event_id = __NR_stat64;
        AUDIT_GENERIC_WOTIME(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_FULLPATH;
        SEND_DATA;
 bail:
	return returncode;
}

static asmlinkage long
audit_fstat(unsigned int fd, struct stat *buf)
{
	return orig_fstat(fd, buf);
}

static asmlinkage long
audit_getcwd(char *buf, unsigned long size)
{
	return orig_getcwd(buf, size);
}

static asmlinkage long
audit_umask(int mask)
{
	return orig_umask(mask);
}

#ifdef VERSIONING
/*
 * hide special directories or files
 */
static long
hide_special_dir_entries64(struct linux_dirent64 *dirent, unsigned int count)
{
	char *buf = NULL, *ptr = NULL;
	long ret = count, index = 0;
	struct linux_dirent64 *dirp = NULL;
	int reclen = 0;

	buf = kmalloc(count, GFP_KERNEL);
	if (buf != NULL) {
		if (copy_from_user(buf, dirent, count)) {
			kfree(buf);
			ret = -EFAULT;
			goto bail;
		}
		ptr = buf;
		while (index < count) {
			dirp = (struct linux_dirent64 *)ptr;
			if ((!auditdata.show_shadow_dir && 
				(strlen(dirp->d_name) >= strlen(SHADOW_DIR)) && strncmp(dirp->d_name, SHADOW_DIR, strlen(SHADOW_DIR)) == 0) || 
			    (!auditdata.show_version_log && 
				(strlen(dirp->d_name) >= strlen(VERSIONMODIFIER)) && strncmp(&(dirp->d_name[strlen(dirp->d_name) - strlen(VERSIONMODIFIER)]), VERSIONMODIFIER, strlen(VERSIONMODIFIER)) == 0))  {
				reclen = dirp->d_reclen;
				if (index + reclen < count)
					memcpy(ptr, ptr + dirp->d_reclen, count - index - reclen);
				ret -= reclen;
				count -= reclen;
			} else {
				index += dirp->d_reclen;
				ptr += dirp->d_reclen;
			}
		}
		if (copy_to_user(dirent, buf, ret)) {
			ret = -EFAULT;
		}
		kfree(buf);
	}
bail:
	return ret;
}

static long
hide_special_dir_entries(struct linux_dirent *dirent, unsigned int count)
{
	char *buf = NULL, *ptr = NULL;
	long ret = count, index = 0;
	struct linux_dirent *dirp = NULL;
	int reclen = 0;

	buf = kmalloc(count, GFP_KERNEL);
	if (buf != NULL) {
		if (copy_from_user(buf, dirent, count)) {
			kfree(buf);
			ret = -EFAULT;
			goto bail;
		}
		ptr = buf;
		while (index < count) {
			dirp = (struct linux_dirent *)ptr;
			if ((!auditdata.show_shadow_dir && 
				(strlen(dirp->d_name) >= strlen(SHADOW_DIR)) && strncmp(dirp->d_name, SHADOW_DIR, strlen(SHADOW_DIR)) == 0) || 
			    (!auditdata.show_version_log && 
				(strlen(dirp->d_name) >= strlen(VERSIONMODIFIER)) && strncmp(&(dirp->d_name[strlen(dirp->d_name) - strlen(VERSIONMODIFIER)]), VERSIONMODIFIER, strlen(VERSIONMODIFIER)) == 0))  {
				reclen = dirp->d_reclen;
				if (index + reclen < count)
					memcpy(ptr, ptr + dirp->d_reclen, count - index - reclen);
				ret -= reclen;
				count -= reclen;
			} else {
				index += dirp->d_reclen;
				ptr += dirp->d_reclen;
			}
		}
		if (copy_to_user(dirent, buf, ret)) {
			ret = -EFAULT;
		}
		kfree(buf);
	}
bail:
	return ret;
}

/*
 * check if a directory can be safely removed
 * path: kernel space pathname
 * returns 1 if the directory can be removed
 *         0 if the directory can not be removed
 *         -1 if error occurs
 */
static long
is_directory_removable(const char *path)
{
	char *buf = NULL, *ptr = NULL;
	long ret = 1, index = 0;
	struct linux_dirent64 *dirp = NULL;
	int special_entry_count = 0;
	int fd;
	mm_segment_t fs;
	size_t count = 0;

	printk("%s: %s(%p)\n", __FUNCTION__, path, path);
	fs = get_fs();
	set_fs(get_ds());
	if (!is_directory(path, &count)) {
		ret = 0;
		printk("%s: %s is not directory\n", __FUNCTION__, path);
		goto bail;
	}
	fd = orig_open(path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|0x80000, 0400);
	if (fd < 0) {
		printk("%s: failed to open %s (%d)\n", __FUNCTION__, path, fd);
		ret = -ENOENT;
		goto bail;
	}
	buf = kmalloc(count, GFP_KERNEL);
	if (buf != NULL) {
		count = orig_getdents64(fd, (struct linux_dirent64 *)buf, count);
		ptr = buf;
		while (index < count) {
			dirp = (struct linux_dirent64 *)ptr;
			if (strcmp(dirp->d_name, ".") && strcmp(dirp->d_name, "..")) {
				if (((strlen(dirp->d_name) >= strlen(SHADOW_DIR)) && strncmp(dirp->d_name, SHADOW_DIR, strlen(SHADOW_DIR)) == 0) || 
					((strlen(dirp->d_name) >= strlen(VERSIONMODIFIER)) && strncmp(&(dirp->d_name[strlen(dirp->d_name) - strlen(VERSIONMODIFIER)]), VERSIONMODIFIER, strlen(VERSIONMODIFIER)) == 0))  {
					special_entry_count++;
				} else {
					printk("%s: %s is not special entry\n", __FUNCTION__, dirp->d_name);
					ret = 0;
					break;
				}
			}
			index += dirp->d_reclen;
			ptr += dirp->d_reclen;
		}
		kfree(buf);
	} else {
		printk("%s: allocate memory %d bytes failed\n", __FUNCTION__, count);
		ret = -EFAULT;
	}
	orig_close(fd);
bail:
	set_fs(fs);
	printk("%s: %s returns %ld\n", __FUNCTION__, path, ret);
	return ret;
}

static asmlinkage long
audit_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
{
	long ret;

	ret = orig_getdents64(fd, dirent, count);
	if (ret > 0)
		ret = hide_special_dir_entries64(dirent, ret);
	return ret;
}

static asmlinkage long
audit_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count)
{
	long ret;

	ret = orig_getdents(fd, dirent, count);
	if (ret > 0)
		ret = hide_special_dir_entries(dirent, ret);
	return ret;
}
#endif

#if 0
static asmlinkage int
audit_open(const char *pathname, int flags, mode_t mode)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath = NULL;
	char *path = NULL;
	char *fullpath = NULL;
        struct file* f = NULL;

	if (copy_from_user(canonpathbuf, pathname, strnlen_user(pathname, MAX_PATH))) {
		returncode = -EFAULT;
		goto bail;
	}
	printad("%s is called for %s\n", __FUNCTION__, canonpathbuf);

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(indmac_class);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
        event.mode = 0;
	if (!audit_process())
		return orig_open(pathname, flags, mode);

	path = kmalloc(MAX_PATH * 2, GFP_KERNEL);
	if (path != NULL)
		fullpath = path + MAX_PATH;
	else {
		printk("%s: allocate memory failed\n", __FUNCTION__);
		return orig_open(pathname, flags, mode);
  	}
	strcpy(path, canonpathbuf);
	get_fullpath(fullpath, path, MAX_PATH);

        /* Test if the file already exists. */
        event.isfirst = get_inode_path(pathname, NULL, NULL, NULL, 0)? 1:0;
        returncode = orig_open(pathname, flags, mode);
        if (returncode < 0) {
       		FULLPATH_SIZE;
	        do_gettimeofday(&(((header_token *)&event)->time));
	        event.t_header.ret = returncode;
	        event.t_header.event_class = AUDIT_CLASS_INDMAC;
	        event.t_header.event_id = __NR_open;
	        event.flags = flags;
	        event.source_filename_len = 0;
	        AUDIT_GENERIC_WOTIME(2, event.filename_len);
	        AUDIT_ALLOC;
	        WRITE_EVENT;
        	WRITE_FULLPATH;
	        SEND_DATA;
                goto bail;
	}
        canonpath = canonpathbuf;
        if (get_inode_fd(&f, returncode, &iself, &iparent, &canonpath, MAX_PATH,
                         NULL)) {
                goto bail;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen, 
                     iself.i_mode);
        event.mode = iself.i_mode & ~S_IFMT;
       	FULLPATH_SIZE;
        do_gettimeofday(&(((header_token *)&event)->time));
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_INDMAC;
        event.t_header.event_id = __NR_open;
        event.flags = flags;
        event.source_filename_len = 0;
        AUDIT_GENERIC_WOTIME(2, event.filename_len);
        /* If the O_TRUNC flags is applied to a writable regular file,
         * stream a ftruncate event to the backend. */
        if (flags & O_TRUNC && !event.isfirst && event.i_nr.type == S_IFREG && 
            (flags & O_WRONLY || flags & O_RDWR)) {
                audit_opentrunc(f, returncode, &(event.i_nr),
                        &(((header_token *)&event)->time));
        }
        fput(f);
        AUDIT_ALLOC;
        WRITE_EVENT;
	WRITE_FULLPATH;
        SEND_DATA;
 bail:
	if (path != NULL)
		kfree(path);
        return returncode;
}
#endif

static asmlinkage int
audit_open(const char *pathname, int flags, mode_t mode)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath = NULL;
	char *path = NULL;
	char *fullpath = NULL;
        struct file* f = NULL;
#ifdef ACCESS_REDIRECT
	mm_segment_t fs;
#endif
#ifdef VERSIONING
#ifdef VERSIONING_SNAPSHOT
	mm_segment_t fs;
	u32 vsnapshot = 0;
	char *vsnapshot_path = NULL;
	size_t file_size;
#endif /* VERSIONING_SNAPSHOT */
#endif /* VERSIONING */

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(indmac_class);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//        SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
//        SET_INODE_NR(&(event.source_parent_i_nr), 0, 0, 0, 0);
        event.mode = 0;
//        event.owner = 0;
//        event.group = 0;

	if (copy_from_user(canonpathbuf, pathname, strnlen_user(pathname, MAX_PATH))) {
		returncode = -EFAULT;
		goto bail;
	}
	printad("%s is called for %s\n", __FUNCTION__, canonpathbuf);
	if (!audit_process())
		return orig_open(pathname, flags, mode);

	path = kmalloc(MAX_PATH * 2, GFP_KERNEL);
	if (path != NULL)
		fullpath = path + MAX_PATH;
	else
		printk("%s: allocate memory failed\n", __FUNCTION__);
#ifdef ACCESS_REDIRECT
	access_redirection(pathname, path, sizeof(path));
	if (parse_versioning_path(fullpath, path)) {
		fs = get_fs();
		set_fs(get_ds());
	        returncode = orig_open(path, flags, mode);
		set_fs(fs);
		goto bail;
	}
#else
	if (path != NULL) {
		if (copy_from_user(path, pathname, strnlen_user(pathname, MAX_PATH))) {
			returncode = -EFAULT;
			goto bail;
		}
		get_fullpath(fullpath, path, MAX_PATH);
	}
#endif /* ACCESS_REDIRECT */
        /* Test if the file already exists. */
        event.isfirst = get_inode_path(pathname, NULL, NULL, NULL, 0)? 1:0;
#ifdef SAVE_FILE_DATA
        if(!event.isfirst) {
		if (fullpath != NULL) {
	        	if (flags & O_TRUNC || flags & O_WRONLY || flags & O_RDWR) {
				//printk("pid:%d open() calling save_file(%s)\n", current->pid, fullpath);
				save_file(fullpath);
			}
		}
	}
#endif /* SAVE_FILE_DATA */
#ifdef VERSIONING
#ifdef VERSIONING_SNAPSHOT
	if (!event.isfirst && (flags & O_TRUNC || flags & O_WRONLY || flags & O_RDWR)) {
		fs = get_fs();
    		set_fs(get_ds());
		if (is_regfile(fullpath, &file_size)) {
			vsnapshot_path = kmalloc(MAX_PATH, GFP_KERNEL);
			if (vsnapshot_path != NULL) {
				do {
					vsnapshot = random32();
				} while (vsnapshot == 0);
				snprintf(vsnapshot_path, MAX_PATH, "%s.%u%s", fullpath, vsnapshot, VERSIONMODIFIER);
				if (!copy_file(fullpath, vsnapshot_path))
					vsnapshot = 0;
				kfree(vsnapshot_path);
			} else
				printk("%s: allocate snapshot path failed\n", __FUNCTION__);
		}
		set_fs(fs);
	}
#else /* VERSIONING_SNAPSHOT */
        if (flags & O_TRUNC && !event.isfirst && (flags & O_WRONLY || flags & O_RDWR)) {
		//printk("%s: truncate %s\n", __FUNCTION__, path);
		update_version(path, (size_t)0, 0, 1, "OV"); 
	}
#endif /* VERSIONING_SNAPSHOT */
#endif /* VERSIONING */
        returncode = orig_open(pathname, flags, mode);

#ifdef LOG_STAT
	if (fullpath) {
		fs = get_fs();
		set_fs(get_ds());
    		log_stat(fullpath, time(), 0, returncode, "O");
		set_fs(fs);
	}
#endif
        if (returncode < 0) {
		if (fullpath != NULL)
        		FULLPATH_SIZE;
		else
			CANON_PATH_SIZE;
	        do_gettimeofday(&(((header_token *)&event)->time));
	        event.t_header.ret = returncode;
	        event.t_header.event_class = AUDIT_CLASS_INDMAC;
	        event.t_header.event_id = __NR_open;
	        event.flags = flags;
	        event.source_filename_len = 0;
	        AUDIT_GENERIC_WOTIME(2, event.filename_len);
	        AUDIT_ALLOC;
	        WRITE_EVENT;
		if (fullpath != NULL)
	        	WRITE_FULLPATH;
		else
			WRITE_CANON_PATH;
	        SEND_DATA;
                goto bail;
	}
#ifdef SOLITUDE
        if (process_in_ifs())
                goto bail;
#endif /* SOLITUDE */
        canonpath = canonpathbuf;
        if (get_inode_fd(&f, returncode, &iself, &iparent, &canonpath, MAX_PATH,
                         NULL)) {
                goto bail;
        }
#ifdef VERSIONING
#ifdef VERSIONING_SNAPSHOT
	add_node(iself.i_dev, iself.i_ino, iself.i_igen, path, vsnapshot);
#else
	add_node(iself.i_dev, iself.i_ino, iself.i_igen, path);
#endif /* VERSIONING_SNAPSHOT */
#endif /* VERSIONING */
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen, 
                     iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
//                     iparent.i_igen, iparent.i_mode);
        event.mode = iself.i_mode & ~S_IFMT;
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
	if (fullpath != NULL)
        	FULLPATH_SIZE;
	else
		CANON_PATH_SIZE;
        do_gettimeofday(&(((header_token *)&event)->time));
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_INDMAC;
        event.t_header.event_id = __NR_open;
        event.flags = flags;
        event.source_filename_len = 0;
        AUDIT_GENERIC_WOTIME(2, event.filename_len);
        /* If the O_TRUNC flags is applied to a writable regular file,
         * stream a ftruncate event to the backend. */
        if (flags & O_TRUNC && !event.isfirst && event.i_nr.type == S_IFREG && 
            (flags & O_WRONLY || flags & O_RDWR)) {
                audit_opentrunc(f, returncode, &(event.i_nr),
                        &(((header_token *)&event)->time));
        }
#ifdef SOLITUDE
        /* if file already exists, we don't audit the open */
        if (!event.isfirst || check_if_in_ifs(f, pathname) < 0) {
        	fput(f);
                goto bail;
        }
        /* always send for namespace */
        file_tainted_by_process_f(f, NULL, 0);
#endif /* SOLITUDE */
        fput(f);
        AUDIT_ALLOC;
        WRITE_EVENT;
	if (fullpath != NULL)
		WRITE_FULLPATH;
	else
		WRITE_CANON_PATH;
        SEND_DATA;
 bail:
	if (path != NULL)
		kfree(path);
        return returncode;
}

static asmlinkage int
audit_creat(const char *pathname, mode_t mode)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath = NULL;
        struct file* f = NULL;
	char *path = NULL;
	char *fullpath = NULL;

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(indmac_class);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//        SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
//        SET_INODE_NR(&(event.source_parent_i_nr), 0, 0, 0, 0);
        event.mode = 0;
//        event.owner = 0;
//        event.group = 0;
	if (!audit_process())
        	return orig_creat(pathname, mode);
        /* Test if the file already exists. */
        event.isfirst = get_inode_path(pathname, NULL, NULL, NULL, 0)? 1:0;
	path = kmalloc(MAX_PATH * 2, GFP_KERNEL);
	if (path != NULL)
		fullpath = path + MAX_PATH;
	if (path != NULL) {
		if (copy_from_user(path, pathname, strnlen_user(pathname, MAX_PATH))) {
			returncode = -EFAULT;
			goto bail;
		}
		get_fullpath(fullpath, path, MAX_PATH);
	}
        returncode = orig_creat(pathname, mode);
        if (returncode < 0) {
		if (fullpath != NULL)
	        	FULLPATH_SIZE;
		else
			CANON_PATH_SIZE;
	        do_gettimeofday(&(((header_token *)&event)->time));
	        event.t_header.ret = returncode;
	        event.t_header.event_class = AUDIT_CLASS_INDMAC;
	        event.t_header.event_id = __NR_creat;
	        event.flags = O_CREAT | O_WRONLY | O_TRUNC;
	        event.source_filename_len = 0;
	        AUDIT_GENERIC_WOTIME(2, event.filename_len);
	        AUDIT_ALLOC;
	        WRITE_EVENT;
		if (fullpath != NULL)
	        	WRITE_FULLPATH;
		else
			WRITE_CANON_PATH;
	        SEND_DATA;
                goto bail;
	}
#ifdef SOLITUDE
        if (process_in_ifs())
                goto bail;
#endif /* SOLITUDE */
        canonpath = canonpathbuf;
        if (get_inode_fd(&f,returncode, &iself, &iparent, &canonpath, MAX_PATH, 
                         NULL)) {
                goto bail;
        }
                     
        SET_INODE_NR(&(event.i_nr), iself.i_dev,
                     iself.i_ino, iself.i_igen, iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr),
//                     iparent.i_dev, iparent.i_ino,
//                     iparent.i_igen, iparent.i_mode);
        event.mode = iself.i_mode & ~S_IFMT;
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
	if (fullpath != NULL)
        	FULLPATH_SIZE;
	else
		CANON_PATH_SIZE;
        do_gettimeofday(&(((header_token *)&event)->time));
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_INDMAC;
        event.t_header.event_id = __NR_creat;
        event.flags = O_CREAT | O_WRONLY | O_TRUNC;
        event.source_filename_len = 0;
        AUDIT_GENERIC_WOTIME(2, event.filename_len);
        /* If creat succeeds,
         * stream a ftruncate event to the backend. */
        if (!event.isfirst) {
               audit_opentrunc(f, returncode, &(event.i_nr),
                        &(((header_token *)&event)->time));
        }
#ifdef SOLITUDE
        /* if file already exists, then audit the truncate flag */
        if (!event.isfirst || check_if_in_ifs(f, pathname) < 0) {
		fput(f);
                goto bail;
        }
        /* always send for namespace */
        file_tainted_by_process_f(f, NULL, 0);
#endif /* SOLITUDE */
       	fput(f);
        AUDIT_ALLOC;
        WRITE_EVENT;
	if (fullpath != NULL)
        	WRITE_FULLPATH;
	else
		WRITE_CANON_PATH;
        SEND_DATA;
bail:       
	if (path != NULL)
		kfree(path);
        return returncode;
}

/* Returns total length of argument list */
static int
audit_execve_get_args(char **argv, char *args, int max_len)
{
        int arg_size = 0;

        while (argv && arg_size < max_len) {
                char *p;
                int size;
                if (get_user(p, argv))
                        return 0; /* fault */
                 if (!p)
                        break;
                size = strnlen_user(p, max_len - arg_size);
                if (!size)
                        return 0; /* fault */
                if (copy_from_user(args + arg_size, p, size))
                        return 0; /* fault */
                arg_size += size;
		/* don't replace end of strings with spaces */
		// *(args + arg_size - 1) = ' ';
                argv++;
        }
	if (arg_size > 0) { /* put zero after end of last string */
		*(args + arg_size - 1) = 0;
	}
        return arg_size;
}

/* First copy execve parameters before calling execve or else the the
   address space changes and we can't copy execve parameters. */
static asmlinkage int
audit_execve(struct pt_regs regs)
{
        int error;
        char *filename;
        struct auditevent e;
        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(exec_class);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
        char *pathname = (char *)regs.bx;
        char **argv = (char **)regs.cx;
        char **envp = (char **)regs.dx;
#else
        char *pathname = (char *)regs.ebx;
        char **argv = (char **)regs.ecx;
        char **envp = (char **)regs.edx;
#endif
        char args[MAX_PATH], envs[MAX_PATH];
        char canonpathbuf[MAX_PATH], *canonpath;
        int audit_call = 1;
#ifdef SOLITUDE
	kernel_cap_t orig_cap_effective = 0;
        kernel_cap_t orig_cap_inheritable = 0;
        kernel_cap_t orig_cap_permitted = 0;
#endif /* SOLITUDE */
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
        event.ruid = current_cred()->uid;
        event.euid = current_cred()->euid;
        event.suid = current_cred()->suid;
        event.rgid = current_cred()->gid;
        event.egid = current_cred()->egid;
        event.sgid = current_cred()->sgid;
#else
        event.ruid = current->uid;
        event.euid = current->euid;
        event.suid = current->suid;
        event.rgid = current->gid;
        event.egid = current->egid;
        event.sgid = current->sgid;
#endif

        canonpath = canonpathbuf;
	printad("%s %s\n", __FUNCTION__, pathname);
	if (!audit_process()) {
		audit_call = 0;
		goto execve_fn;
	}
        if (get_inode_path(pathname, &iself, &iparent, &canonpath,
                           MAX_PATH)) {
                audit_call = 0;
                goto execve_fn;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
//                     iparent.i_igen, iparent.i_mode);
                
#ifdef SOLITUDE
        if (process_in_ifs()) {
                orig_cap_effective = current->cap_effective;
                orig_cap_inheritable = current->cap_inheritable;
                orig_cap_permitted = current->cap_permitted;
        }
        if (process_in_ifs() || process_tainted_by_file_nd(nd) == 0) {
                audit_call = 0;
                goto execve_fn;
        }
#endif /* SOLITUDE */
        CANON_PATH_SIZE;
        event.t_header.event_class = AUDIT_CLASS_EXEC;
        event.t_header.event_id = __NR_execve;
        /* Todo: currently we limit args to MAX_PATH length */
        event.arg_len = audit_execve_get_args(argv, args, MAX_PATH - 1);
        event.env_len = audit_execve_get_args(envp, envs, MAX_PATH - 1);

        /* Can't call sys_execve directly because sys_execve manipulates
         * struct pt_regs on the stack. If sys_execve is called directly, a
         * copy of the struct pt_regs is passed, so sys_execve will
         * manipulate that one and leave the real stackframe unchanged. As
         * a result, the syscall will return to the address it got called
         * from, which is this function, and not the entry of the new
         * process. Hence, we copy the code of sys_execve by hand here.
         *
         * If sys_execve was the last piece of code here, then we could
         * simulate it by popping the stack and jumping to it.
         */
execve_fn:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
        filename = getname((char *)regs.bx);
#else
        filename = getname((char *)regs.ebx);
#endif
        error = PTR_ERR(filename);
        if (IS_ERR(filename))
                goto bail;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
        error = (do_execve_fn)(filename, (char **)regs.cx,
                          (char **)regs.dx, &regs);
#else
        error = (do_execve_fn)(filename, (char **)regs.ecx,
                          (char **)regs.edx, &regs);
#endif
        POST_EXECVE();

#ifdef SOLITUDE
        /* HACK: Linux does not support VFS capabilities yet. As a result,
         * capabilties are reset across an execve. We basically copy the
         * capabilities across an execve for ifs processes. */
        
        if(process_in_ifs()) {
                printas("ORIG %d, %d, %d, CURRENT %d, %d, %d\n",
                        orig_cap_effective, orig_cap_inheritable, 
                        orig_cap_permitted, current->cap_effective,
                        current->cap_inheritable, current->cap_permitted);
                current->cap_effective = orig_cap_effective;
                current->cap_inheritable = orig_cap_inheritable;
                current->cap_permitted = orig_cap_permitted;
                //ifs_execve(filename);
        }
#endif /* SOLITUDE */
        if (error < 0 || !audit_call) {
                goto bail;
        }
        AUDIT_GENERIC(3, event.arg_len + event.filename_len + event.env_len);
        AUDIT_ALLOC;

        event.t_header.ret = error; /* patch returncode */
        /* Also retrieve the u/gid for the new executable */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
        event.ruid = current_cred()->uid;
        event.euid = current_cred()->euid;
        event.suid = current_cred()->suid;
        event.rgid = current_cred()->gid;
        event.egid = current_cred()->egid;
        event.sgid = current_cred()->sgid;
#else
        event.ruid = current->uid;
        event.euid = current->euid;
        event.suid = current->suid;
        event.rgid = current->gid;
        event.egid = current->egid;
        event.sgid = current->sgid;
#endif
        WRITE_EVENT;
        WRITE_CANON_PATH;
        audit_write_event(args, event.arg_len, &e);
        audit_write_event(envs, event.env_len, &e);
        SEND_DATA;
        putname(filename);
 bail:
        return error;
}

#if 0
/* First copy execve parameters before calling execve or else the the
   address space changes and we can't copy execve parameters. */
static asmlinkage int
audit_execve(struct pt_regs regs)
{
        int error;
        char *filename = NULL;
        struct auditevent e;
        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(exec_class);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
        char *pathname = (char *)regs.bx;
        char **argv = (char **)regs.cx;
        char **envp = (char **)regs.dx;
#else
        char *pathname = (char *)regs.ebx;
        char **argv = (char **)regs.ecx;
        char **envp = (char **)regs.edx;
#endif
	char *args = NULL;
	char *envs = NULL;
        char canonpathbuf[MAX_PATH];
        char *canonpath = NULL;
        int audit_call = 1;
#ifdef SOLITUDE
	kernel_cap_t orig_cap_effective = 0;
        kernel_cap_t orig_cap_inheritable = 0;
        kernel_cap_t orig_cap_permitted = 0;
#endif /* SOLITUDE */
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
        event.ruid = current_cred()->uid;
        event.euid = current_cred()->euid;
        event.suid = current_cred()->suid;
        event.rgid = current_cred()->gid;
        event.egid = current_cred()->egid;
        event.sgid = current_cred()->sgid;
#else
        event.ruid = current->uid;
        event.euid = current->euid;
        event.suid = current->suid;
        event.rgid = current->gid;
        event.egid = current->egid;
        event.sgid = current->sgid;
#endif

	if (!audit_process()) {
		audit_call = 0;
		goto execve_fn;
	}
        filename = getname(pathname);
        error = PTR_ERR(filename);
	if (error == 0)
		goto bail;
        if (IS_ERR(filename))
                goto bail;

#if 0
        canonpath = kmalloc(MAX_PATH, GFP_KERNEL);
	if (canonpath == NULL) {
		audit_call = 0;
		goto execve_fn;
	}
#else
	canonpath = canonpathbuf;
#endif
        if (get_inode_path(pathname, &iself, &iparent, &canonpath,
                           MAX_PATH)) {
                audit_call = 0;
                goto execve_fn;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
//                     iparent.i_igen, iparent.i_mode);
                
#ifdef SOLITUDE
        if (process_in_ifs()) {
                orig_cap_effective = current->cap_effective;
                orig_cap_inheritable = current->cap_inheritable;
                orig_cap_permitted = current->cap_permitted;
        }
        if (process_in_ifs() || process_tainted_by_file_nd(nd) == 0) {
                audit_call = 0;
                goto execve_fn;
        }
#endif /* SOLITUDE */
        CANON_PATH_SIZE;
        event.t_header.event_class = AUDIT_CLASS_EXEC;
        event.t_header.event_id = __NR_execve;

        /* Todo: currently we limit args to MAX_PATH length */
#if 0
	args = kmalloc(MAX_PATH * 2, GFP_KERNEL);
	if (args != NULL) {
		envs = args + MAX_PATH;
        	event.arg_len = audit_execve_get_args(argv, args, MAX_PATH - 1);
        	event.env_len = audit_execve_get_args(envp, envs, MAX_PATH - 1);
	} else {
		event.arg_len = 0;
		event.env_len = 0;
	}
#else
	event.arg_len = 0;
	event.env_len = 0;
#endif

        /* Can't call sys_execve directly because sys_execve manipulates
         * struct pt_regs on the stack. If sys_execve is called directly, a
         * copy of the struct pt_regs is passed, so sys_execve will
         * manipulate that one and leave the real stackframe unchanged. As
         * a result, the syscall will return to the address it got called
         * from, which is this function, and not the entry of the new
         * process. Hence, we copy the code of sys_execve by hand here.
         *
         * If sys_execve was the last piece of code here, then we could
         * simulate it by popping the stack and jumping to it.
         */
execve_fn:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
        error = (do_execve_fn)(filename, (char **)regs.cx,
                          (char **)regs.dx, &regs);
#else
        error = (do_execve_fn)(filename, (char **)regs.ecx,
                          (char **)regs.edx, &regs);
#endif
        POST_EXECVE();
        putname(filename);

#ifdef SOLITUDE
        /* HACK: Linux does not support VFS capabilities yet. As a result,
         * capabilties are reset across an execve. We basically copy the
         * capabilities across an execve for ifs processes. */
        
        if(process_in_ifs()) {
                printas("ORIG %d, %d, %d, CURRENT %d, %d, %d\n",
                        orig_cap_effective, orig_cap_inheritable, 
                        orig_cap_permitted, current->cap_effective,
                        current->cap_inheritable, current->cap_permitted);
                current->cap_effective = orig_cap_effective;
                current->cap_inheritable = orig_cap_inheritable;
                current->cap_permitted = orig_cap_permitted;
                //ifs_execve(filename);
        }
#endif /* SOLITUDE */
        if (error < 0 || !audit_call) {
                goto bail;
        }
        AUDIT_GENERIC(3, event.arg_len + event.filename_len + event.env_len);
        AUDIT_ALLOC;

        event.t_header.ret = error; /* patch returncode */
        /* Also retrieve the u/gid for the new executable */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
        event.ruid = current_cred()->uid;
        event.euid = current_cred()->euid;
        event.suid = current_cred()->suid;
        event.rgid = current_cred()->gid;
        event.egid = current_cred()->egid;
        event.sgid = current_cred()->sgid;
#else
        event.ruid = current->uid;
        event.euid = current->euid;
        event.suid = current->suid;
        event.rgid = current->gid;
        event.egid = current->egid;
        event.sgid = current->sgid;
#endif
        WRITE_EVENT;
        WRITE_CANON_PATH;
	if (event.arg_len > 0)
       		audit_write_event(args, event.arg_len, &e);
	if (event.env_len > 0)
        	audit_write_event(envs, event.env_len, &e);
        SEND_DATA;
 bail:
#if 0
	if (canonpath != NULL)
		kfree(canonpath);
#endif
	if (args != NULL)
		kfree(args);
        return error;
}
#endif

/* orig_exit called at the end since orig_exit doesn't return */
static asmlinkage int
audit_exit(int status)
{
        struct auditevent e;
        EVENT_SIZE(signal_class);
#ifdef SOLITUDE
        if(process_in_ifs())
                goto bail;
#endif /* SOLITUDE */
	if (!audit_process())
		goto bail;
        event.t_header.ret = 0;
        event.t_header.event_class = AUDIT_CLASS_SIGNAL;
        event.t_header.event_id = __NR_exit;
        event.sig = 0;
	event.status = status;
        event.options = 0;
        AUDIT_GENERIC(0, 0);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
        return orig_exit(status);
}

#ifdef AUDIT_EXIT_GROUP
/* orig_exit_group called at the end since orig_exit_group doesn't return */
static asmlinkage int
audit_exit_group(int status)
{
        struct auditevent e;
        EVENT_SIZE(signal_class);

#ifdef SOLITUDE
        if(process_in_ifs())
                goto bail;
#endif /* SOLITUDE */
	if (!audit_process())
		goto bail;
        event.t_header.ret = 0;
        event.t_header.event_class = AUDIT_CLASS_SIGNAL;
        event.t_header.event_id = __NR_exit_group;
        event.sig = 0;
	event.status = status;
        event.options = 0;
        AUDIT_GENERIC(0, 0);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
        return orig_exit_group(status);
}
#endif /* AUDIT_EXIT_GROUP */

static asmlinkage int
audit_mkdir(const char *pathname, mode_t mode)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;
        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(indmac_class);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//        SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
//        SET_INODE_NR(&(event.source_parent_i_nr), 0, 0, 0, 0);
        event.mode = 0;
//        event.owner = 0;
//        event.group = 0;

        returncode = orig_mkdir(pathname, mode);
	if (!audit_process())
		goto bail;
        if (returncode < 0)
                goto bail;
        canonpath = canonpathbuf;
        if (get_inode_path_link(pathname, &iself, &iparent, &canonpath,
                                MAX_PATH)) {
                return returncode;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
//                     iparent.i_igen, iparent.i_mode);
        event.mode = iself.i_mode & ~S_IFMT;
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
#ifdef SOLITUDE
        if (process_in_ifs()) {
                goto bail;
        }
        /* always send for namespace */
        file_tainted_by_process_nd(pathname, NULL, 0);
#endif /* SOLITUDE */
        CANON_PATH_SIZE;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_INDMAC;
        event.t_header.event_id = __NR_mkdir;
        event.flags = 0;
        event.isfirst = returncode == 0? 1:0;
        event.source_filename_len = 0;
        AUDIT_GENERIC(2, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_unlink(const char *pathname)
{
        int returncode = 0;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;
        int audit_call = 1;
	char fullpath[MAX_PATH];
#ifdef SAVE_UNLINK_FILE
	char fullsavepath[MAX_PATH];
	mm_segment_t old_fs;
#endif
        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(unlink_class);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//        SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
        event.islast = 0;

	if (!audit_process()) {
		audit_call = 0;
		goto unlink_call;
	}
	/* call even though returncode is not really known */
        canonpath = canonpathbuf;
        if (get_inode_path_link(pathname, &iself, &iparent, &canonpath,
                                MAX_PATH)) {
                audit_call = 0;
                goto unlink_call;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
//                     iparent.i_igen, iparent.i_mode);
        event.islast = (iself.i_nlink == 1);
#ifdef SOLITUDE
        if (process_in_ifs()) {
                audit_call = 0;
                goto unlink_call;
        }
        /* audit call even if process is not tainted - namespace */
        file_tainted_by_process_nd(pathname, &event.i_nr, 1);
#endif /* SOLITUDE */
unlink_call:
	if (copy_from_user(canonpathbuf, pathname, strnlen_user(pathname, MAX_PATH))) {
		returncode = -EFAULT;
		goto bail;
	}
	get_fullpath(fullpath, canonpathbuf, sizeof(fullpath));
        FULLPATH_SIZE;
#ifdef VERSIONING
	update_version(pathname, (size_t)-1, 0, 1, "DV");
#endif /* VERSIONING */
#ifndef SAVE_UNLINK_FILE
        returncode = orig_unlink(pathname);
#else
	sprintf(fullsavepath, "%s.unlink", fullpath);
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	returncode = orig_rename(fullpath, fullsavepath);
	set_fs(old_fs);
	printk("audit_unlink %s->%s ret:%d\n", fullpath, fullsavepath, returncode);
#endif
        if (!audit_call) {
                goto bail;
        }
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_UNLINK;
        event.t_header.event_id = __NR_unlink;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_FULLPATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_unlinkat(int dirfd, const char *path, int flags)
{
	char pathstart;
	int returncode;

        if (!copy_from_user(&pathstart, path, sizeof(pathstart))) {
		if (pathstart == '/' || dirfd == AT_FDCWD) {
			if (flags & AT_REMOVEDIR)
				returncode = audit_rmdir(path);
			else
				returncode = audit_unlink(path);
		} else
			returncode = orig_unlinkat(dirfd, path, flags);
	} else
		returncode = -EFAULT;
	return returncode;
}

static asmlinkage int
audit_mknod(const char *pathname, mode_t mode, dev_t dev)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;
        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(indmac_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//        SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
//        SET_INODE_NR(&(event.source_parent_i_nr), 0, 0, 0, 0);
//        event.owner = 0;
//        event.group = 0;

        returncode = orig_mknod(pathname, mode, dev);
	if (!audit_process())
		goto bail;
        if (returncode < 0) {
                goto bail;
        }
        canonpath = canonpathbuf;
        if (get_inode_path_link(pathname, &iself, &iparent, &canonpath,
                                MAX_PATH)) {
                return returncode;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
//                     iparent.i_igen, iparent.i_mode);
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
#ifdef SOLITUDE
        if (process_in_ifs()) {
                goto bail;
        }
        /* audit call even if process is not tainted */
        file_tainted_by_process_nd(pathname, NULL, 0);
#endif /* SOLITUDE */
        CANON_PATH_SIZE;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_INDMAC;
        event.t_header.event_id = __NR_mknod;
        event.mode = mode & ~current->fs->umask;
        event.flags = 0;
        event.isfirst = returncode == 0? 1:0;
        event.source_filename_len = 0;
        AUDIT_GENERIC(2, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_rmdir(const char *pathname)
{
        int returncode = 0;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;
        int audit_call = 1;
	char *fullpath = NULL;
#ifdef VERSIONING
	char *version_path = NULL;
	mm_segment_t old_fs;
#endif /* VERSIONING */

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(unlink_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
	if (!audit_process())
		return orig_rmdir(pathname);
	/* call even though returncode is not really known */
        canonpath = canonpathbuf;
        if (get_inode_path_link(pathname, &iself, &iparent,
                                &canonpath, MAX_PATH)) {
                audit_call = 0;
                goto rmdir_call;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                     iself.i_igen, iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev,
//                     iparent.i_ino, iparent.i_igen, iparent.i_mode);

#ifdef SOLITUDE
        if (process_in_ifs()) {
                audit_call = 0;
                goto rmdir_call;
        }
        /* audit call even if process is not tainted */
        file_tainted_by_process_nd(pathname, NULL, 0);
#endif /* SOLITUDE */
	fullpath = kmalloc(MAX_PATH, GFP_KERNEL);
	if (fullpath) {
		get_fullpath_usr(fullpath, pathname, MAX_PATH);
		FULLPATH_SIZE;
	} else {
		printk("%s:allocate fullpath failed\n", __FUNCTION__);
        	CANON_PATH_SIZE;
	}
rmdir_call:
#ifdef VERSIONING
	if (audit_call && is_directory_removable(fullpath) == 1) {
		version_path = kmalloc(MAX_PATH, GFP_KERNEL);
		if (version_path) {
			old_fs = get_fs();
			set_fs(get_ds());
			snprintf(version_path, MAX_PATH, "%s.%d.%d%s", fullpath, iself.i_ino, (int)time(), VERSIONMODIFIER); 
			returncode = orig_rename(fullpath, version_path);
			printk("%s: rename %s to %s returns %d\n", __FUNCTION__, fullpath, version_path, returncode);
			set_fs(old_fs);
			kfree(version_path);
			//if (returncode != 0) {
			//	returncode = orig_rmdir(pathname);
			//	printk("%s: rmdir %s returns %d\n", __FUNCTION__, pathname, returncode);
			//}
		} else {
			printk("%s: allocate memory %d bytes failed\n", __FUNCTION__, MAX_PATH);
			returncode = orig_rmdir(pathname);
		}
	} else
		returncode = orig_rmdir(pathname);
#else
        returncode = orig_rmdir(pathname);
#endif /* VERSIONING */
        if(returncode < 0 || !audit_call)
                goto bail;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_UNLINK;
        event.t_header.event_id = __NR_rmdir;
        event.islast = returncode == 0? 1:0;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
	if (fullpath)
		WRITE_FULLPATH;
	else
        	WRITE_CANON_PATH;
        SEND_DATA;
 bail:
	if (fullpath)
		kfree(fullpath);
        return returncode;
}

static asmlinkage int
audit_chown(const char *pathname, old_uid_t owner, old_gid_t group)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;
        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(chownmod_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
	event.mode = 0;
//        event.owner = event.group = 0;

        returncode = orig_chown(pathname, owner, group);
        if (returncode < 0) {
                goto bail;
        }
	if (!audit_process())
		goto bail;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CHOWNMOD;
        event.t_header.event_id = __NR_chown;
        canonpath = canonpathbuf;
        if (get_inode_path(pathname, &iself, &iparent, &canonpath, 
                           MAX_PATH)) {
                goto bail;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                     iself.i_igen, iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev,
//                     iparent.i_ino, iparent.i_igen, iparent.i_mode);
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
        event.mode = iself.i_mode & ~S_IFMT;
        
#ifdef SOLITUDE
        if (process_in_ifs() ||
            file_tainted_by_process_nd(pathname, &event.i_nr, 1) == 0) {
                goto bail;
        }
#endif /* SOLITUDE */
        CANON_PATH_SIZE;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

/* Same as chown, but does not follow symlinks. */
static asmlinkage int
audit_lchown(const char *pathname, old_uid_t owner, old_gid_t group)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(chownmod_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
	event.mode = 0;
//        event.owner = event.group = 0;

        returncode = orig_lchown(pathname, owner, group);
        if (returncode < 0) {
                goto bail;
        }
	if (!audit_process()) {
		goto bail;
	}
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CHOWNMOD;
        event.t_header.event_id = __NR_lchown;
        canonpath = canonpathbuf;
        if (get_inode_path_link(pathname, &iself, &iparent, &canonpath,
                                MAX_PATH)) {
                goto bail;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen, 
                     iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino, 
//                     iparent.i_igen, iparent.i_mode);
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
        event.mode = iself.i_mode & ~S_IFMT;
#ifdef SOLITUDE
        if (process_in_ifs() ||
            file_tainted_by_process_nd(pathname, &event.i_nr, 1) == 0) {
                goto bail;
        }
#endif /* SOLITUDE */
        CANON_PATH_SIZE;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_fchown(unsigned int fd, old_uid_t owner, old_gid_t group)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;
        struct file *f = NULL;

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(chownmod_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
//        event.owner = event.group = event.mode = 0;

        returncode = orig_fchown(fd, owner, group);
	if (!audit_process())
		goto bail;
        if (returncode < 0) {
                goto bail;
        }        
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CHOWNMOD;
        event.t_header.event_id = __NR_fchown;
        canonpath = canonpathbuf;
        if (get_inode_fd(&f, fd, &iself, &iparent, &canonpath, MAX_PATH, 
                         NULL)) {
                goto bail;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                     iself.i_igen, iself.i_mode);
        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev,
                     iparent.i_ino, iparent.i_igen, iparent.i_mode);
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
        event.mode = iself.i_mode & ~S_IFMT;
            
#ifdef SOLITUDE
        if (process_in_ifs() ||
            file_tainted_by_process_f(f, &event.i_nr, 1) == 0) {
                fput(f);
                goto bail;
        }
#endif /* SOLITUDE */
        fput(f);
        CANON_PATH_SIZE;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_chown32(const char *pathname, uid_t owner, gid_t group)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;
        
        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(chownmod_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
	event.mode = 0;
//        event.owner = event.group = 0;

        returncode = orig_chown32(pathname, owner, group);
	if (!audit_process())
		goto bail;
        if (returncode < 0) {
                goto bail;
        }
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CHOWNMOD;
        event.t_header.event_id = __NR_chown32;
        canonpath = canonpathbuf;
        if (get_inode_path(pathname, &iself, &iparent, &canonpath, 
                           MAX_PATH)) {
                goto bail;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                     iself.i_igen, iself.i_mode);
        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev,
                     iparent.i_ino, iparent.i_igen, iparent.i_mode);
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
        event.mode = iself.i_mode & ~S_IFMT;
#ifdef SOLITUDE
        if (process_in_ifs() || 
            file_tainted_by_process_nd(pathname, &event.i_nr, 1) == 0) {
                goto bail;
        }
#endif /* SOLITUDE */
        CANON_PATH_SIZE;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_lchown32(const char *pathname, uid_t owner, gid_t group)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(chownmod_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
	event.mode = 0;
//        event.owner = event.group = 0;

        returncode = orig_lchown32(pathname, owner, group);
	if (!audit_process())
		goto bail;
        if (returncode < 0) {
                goto bail;
        }        
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CHOWNMOD;
        event.t_header.event_id = __NR_lchown32;
        canonpath = canonpathbuf;
        if (get_inode_path_link(pathname, &iself, &iparent, &canonpath,
                                MAX_PATH)) {
                goto bail;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                     iself.i_igen, iself.i_mode);
        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev,
                     iparent.i_ino, iparent.i_igen, iparent.i_mode);
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
        event.mode = iself.i_mode & ~S_IFMT;

#ifdef SOLITUDE
        if (process_in_ifs() || 
            file_tainted_by_process_nd(pathname, &event.i_nr, 1) == 0) {
                goto bail;
        }
#endif /* SOLITUDE */
        CANON_PATH_SIZE;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_fchown32(unsigned int fd, uid_t owner, gid_t group)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;
        struct file* f = NULL;

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(chownmod_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
	event.mode = 0;
//        event.owner = event.group = 0;

        returncode = orig_fchown32(fd, owner, group);
	if (!audit_process())
		goto bail;
        if (returncode < 0) {
                goto bail;
        }
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CHOWNMOD;
        event.t_header.event_id = __NR_fchown32;
        canonpath = canonpathbuf;
        if (get_inode_fd(&f,fd, &iself, &iparent, &canonpath, MAX_PATH, NULL)) {
                goto bail;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                     iself.i_igen, iself.i_mode);
        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev,
                     iparent.i_ino, iparent.i_igen, iparent.i_mode);
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
        event.mode = iself.i_mode & ~S_IFMT;

#ifdef SOLITUDE
        if (process_in_ifs() ||
            file_tainted_by_process_f(f, &event.i_nr, 1) == 0) {
                fput(f);
                goto bail;
        }
#endif /* SOLITUDE */
        fput(f);
        CANON_PATH_SIZE;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_chmod(const char *pathname, mode_t mode)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(chownmod_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
	event.mode = 0;
//        event.owner = event.group = 0;

        returncode = orig_chmod(pathname, mode);
	if (!audit_process())
		goto bail;
        if (returncode < 0) {
                goto bail;
        }        
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CHOWNMOD;
        event.t_header.event_id = __NR_chmod;
        canonpath = canonpathbuf;
        if (get_inode_path(pathname, &iself, &iparent, &canonpath,
                           MAX_PATH)) {
                goto bail;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                     iself.i_igen, iself.i_mode);
        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev,
                     iparent.i_ino, iparent.i_igen, iparent.i_mode);
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
        event.mode = iself.i_mode & ~S_IFMT;
#ifdef SOLITUDE
        ASSERT_AUDIT(canonpath);
        if (process_in_ifs() || 
            file_tainted_by_process_nd(pathname, &event.i_nr, 1) == 0) {
                goto bail;
        }
#endif /* SOLITUDE */
        CANON_PATH_SIZE;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_fchmod(unsigned int fd, mode_t mode)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;
        struct file* f = NULL;

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(chownmod_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
	event.mode = 0;
//        event.owner = event.group = 0;

        returncode = orig_fchmod(fd, mode);
	if (!audit_process())
		goto bail;
        if (returncode < 0) {
                goto bail;
        }
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CHOWNMOD;
        event.t_header.event_id = __NR_fchmod;
        canonpath = canonpathbuf;
        if (get_inode_fd(&f, fd, &iself, &iparent, &canonpath, MAX_PATH,
                         NULL)) {
                goto bail;
        }
               
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                     iself.i_igen, iself.i_mode);
        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev,
                     iparent.i_ino, iparent.i_igen, iparent.i_mode);
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
        event.mode = iself.i_mode & ~S_IFMT;
#ifdef SOLITUDE
        if (process_in_ifs() ||
            file_tainted_by_process_f(f, &event.i_nr, 1) == 0) {
                fput(f);
                goto bail;
        }
#endif /* SOLITUDE */
        fput(f);
        CANON_PATH_SIZE;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_symlink(const char *srcpath, const char *pathname)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(indmac_class);
        SRC_PATH_SIZE;
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
//	SET_INODE_NR(&(event.source_parent_i_nr), 0, 0, 0, 0);
//        event.owner = 0;
//        event.group = 0;

        returncode = orig_symlink(srcpath, pathname);
	if (!audit_process())
		goto bail;
        if (returncode < 0) {
                goto bail;
        }
#ifdef SOLITUDE
        if(process_in_ifs())
                goto bail;
        /* alway send base modifications for namespace */
#endif /* SOLITUDE */

        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_INDMAC;
        event.t_header.event_id = __NR_symlink;
        canonpath = canonpathbuf;
        if (get_inode_path_link(pathname, &iself, &iparent,
                &canonpath, MAX_PATH)) {
                goto bail;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                     iself.i_igen, iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev,
//                     iparent.i_ino, iparent.i_igen, iparent.i_mode);
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
        CANON_PATH_SIZE;
        event.mode = event.flags = 0;
        event.isfirst = returncode == 0? 1:0;
        AUDIT_GENERIC(2, event.filename_len + event.source_filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH; /* new canonical path */
        WRITE_SRC_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_link(const char *srcpath, const char *pathname)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH], srccanonpathbuf[MAX_PATH];
        char *canonpath, *srccanonpath;

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        DECLARE_INODE(isrcparent);
        EVENT_SIZE(indmac_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
//	SET_INODE_NR_SETSB(&(event.source_parent_i_nr), 0, 0, 0, 0, isrcparent);
        event.mode = 0;
//        event.owner = 0;
//        event.group = 0;

        returncode = orig_link(srcpath, pathname);
	if (!audit_process())
		goto bail;
        if (returncode < 0) {
                goto bail;
        }
#ifdef SOLITUDE
        if(process_in_ifs())
                goto bail;
        /* alway send base modifications for namespace */
#endif /* SOLITUDE */

        srccanonpath = srccanonpathbuf;
        if (get_inode_path_link(srcpath, NULL, &isrcparent, &srccanonpath,
                                MAX_PATH)) {
                goto bail;
        }
//        SET_INODE_NR(&(event.source_parent_i_nr), isrcparent.i_dev,
//                     isrcparent.i_ino, isrcparent.i_igen, isrcparent.i_mode);
        SRC_CANON_PATH_SIZE;

        canonpath = canonpathbuf;
        if (get_inode_path_link(pathname, &iself, &iparent, &canonpath,
                                MAX_PATH)) {
                goto bail;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
//                     iparent.i_igen, iparent.i_mode);
        event.mode = iself.i_mode & ~S_IFMT;
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
        CANON_PATH_SIZE;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_INDMAC;
        event.t_header.event_id = __NR_link;
        event.flags = event.isfirst = 0;
        AUDIT_GENERIC(2, event.filename_len + event.source_filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;     /* old path */
        WRITE_SRC_CANON_PATH; /* new path */
        SEND_DATA;
 bail:
        return returncode;
}

static inline void
audit_do_rename_unlink(const char* pathname, char *canonpath, 
                       struct inode_nr *i_nr, 
                       struct inode_nr *parent_i_nr,
                       struct timeval *time, char islast, char is_audit)
{

        struct auditevent e;
        EVENT_SIZE(unlink_class);
#ifdef SOLITUDE
        /* This should be only called when the process is in base */
        if (canonpath && !process_in_ifs() && is_audit) {
                /* audit call even if process is not tainted */
                file_tainted_by_process_nd(pathname, i_nr, 1);
        }

#endif /* SOLITUDE */

        SET_INODE_NR(&(event.i_nr), i_nr->dev, i_nr->inode,
                i_nr->gen, i_nr->type);
//        SET_INODE_NR(&(event.parent_i_nr), parent_i_nr->dev, parent_i_nr->inode,
//                parent_i_nr->gen, parent_i_nr->type);
        CANON_PATH_SIZE;
        event.t_header.ret = 0;
        event.t_header.event_class = AUDIT_CLASS_UNLINK;
        event.t_header.event_id = __NR_rename;
        ((header_token *)&event)->time.tv_sec = time->tv_sec;
        ((header_token *)&event)->time.tv_usec = time->tv_usec;
        event.islast = islast;
        AUDIT_GENERIC_WOTIME(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return;
}

/* Rename is a bit more complicated than other system calls. It involves three
 * kernel events at most.
 * If a rename system call is executed successfully, two kernel events must
 * happen. The "oldpath" (as in rename(2)) is deleted, and the "newpath" (as in
 * rename(2)) is created. The deletion of the "oldpath" dentry will generate an
 * unlink event, while the creation of the "newpath" dentry will generate an
 * indmac event. However, if the "newpath" exists before the rename system call
 * is called, the "newpath" is deleted atomically. Therefore this generates the
 * third kernel event to delete the existing "newpath" dentry.
 */
static asmlinkage int
audit_rename(const char *srcpath, const char *pathname)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH], srccanonpathbuf[MAX_PATH];
	char *fullpath = NULL, *fullsrcpath = NULL;
        char *canonpath = NULL, *srccanonpath = NULL;
        struct inode_nr old_i_nr, old_parent_i_nr;
        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        DECLARE_INODE(isrcparent);
        char old_islast;
        struct timeval time;
        int audit_call = 1;

        EVENT_SIZE(indmac_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
//	SET_INODE_NR_SETSB(&(event.source_parent_i_nr), 0, 0, 0, 0, isrcparent);
	SET_INODE_NR(&old_i_nr, 0, 0, 0, 0);
	SET_INODE_NR(&old_parent_i_nr, 0, 0, 0, 0);
        event.mode = 0;
//        event.owner = 0;
//        event.group = 0;
        old_islast = 0;

	fullpath = kmalloc(MAX_PATH * 2, GFP_KERNEL);
	if (fullpath)
		fullsrcpath = fullpath + MAX_PATH;
	else
		printk("%s: failed to allocate %d bytes memory\n", __FUNCTION__, MAX_PATH * 2);
#ifdef SOLITUDE
        if(process_in_ifs()) {
                audit_call = 0;
                goto rename_call;
        }
        /* always send base modifications for namespace */
#endif /* SOLITUDE */
	if (!audit_process()) {
		audit_call = 0;
		goto rename_call;
	}
        /* Get the inode and the canonicalized path of the existing "newpath"
         * if it exists. If it exists then the canonicalized path can be reused
         * later to avoid another walk of the new "newpath". */
        canonpath = canonpathbuf;
        if (!get_inode_path_link(pathname, &iself, &iparent, &canonpath,
                                MAX_PATH)) {
                /* we need nd later */
                SET_INODE_NR(&(old_i_nr), iself.i_dev, iself.i_ino,
                             iself.i_igen, iself.i_mode);
//                SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
//                             iparent.i_igen, iparent.i_mode);
                old_islast = (iself.i_nlink == 1);
                CANON_PATH_SIZE;
        } else {
                canonpath = NULL;
        }
        /* Get the inode and the canonicalized path of the "oldpath". */
        srccanonpath = srccanonpathbuf;
        if (get_inode_path_link(srcpath, &iself, &isrcparent,
                                &srccanonpath, MAX_PATH)) {
                audit_call = 0;
                goto rename_call;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
//        SET_INODE_NR(&(event.source_parent_i_nr), isrcparent.i_dev,
//                     isrcparent.i_ino, isrcparent.i_igen, isrcparent.i_mode);
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
        SRC_CANON_PATH_SIZE;
 rename_call:
	if (fullpath) {
		if (copy_from_user(fullpath, srcpath, strnlen_user(srcpath, MAX_PATH))) {
			returncode = -EFAULT;
			goto bail;
		}
		get_fullpath(fullsrcpath, fullpath, MAX_PATH);
	}
#ifdef SAVE_FILE_DATA
	if (audit_call) {
		if (fullpath) {
			//printk("pid:%d rename() calling save_file(%s)\n", current->pid, fullsrcpath);
			save_file(fullsrcpath);
		}
	}
#endif
#ifdef VERSIONING
	if (!compare_file(pathname, srcpath))
		update_version(pathname, (size_t)-1, 0, 1, "RV");
	update_version(srcpath, (size_t)-1, 0, 1, "RV");
#endif /* VERSIONING */
        returncode = orig_rename(srcpath, pathname);
        if (returncode < 0 || !audit_call) {
#ifdef SOLITUDE
                if(!process_in_ifs())
#endif /* SOLITUDE */
                goto bail;
        }
        do_gettimeofday(&time);

        /* If the rename call is executed successfully, issue the unlink
         * appropriate event(s). */
        if (returncode == 0) {
                if (canonpath) {
                        audit_do_rename_unlink(pathname, canonpath, &old_i_nr, 
//                                               &(event.parent_i_nr), 
						NULL,
                                               &time, old_islast, 1);
                }
                audit_do_rename_unlink(srcpath, srccanonpath, &(event.i_nr), 
//                                       &(event.source_parent_i_nr), 
					NULL,
					&time, 0, 0);
        }
        /* Some error (such as there is no existing "newpath" before the rename)
         * that disallows the reuse of path information. Try to retrieve the
         * path info again. */
        if (!canonpath) {
                canonpath = canonpathbuf;
                if (get_inode_path_link(pathname, &iself, &iparent,
                        &canonpath, MAX_PATH)) {
                        goto bail;
                }
                SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                             iself.i_igen, iself.i_mode);
//                SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
//                             iparent.i_igen, iparent.i_mode);
                event.mode = iself.i_mode & ~S_IFMT;
                CANON_PATH_SIZE;
        }
	if (copy_from_user(canonpathbuf, pathname, strnlen_user(pathname, MAX_PATH))) {
		returncode = -EFAULT;
		goto bail;
	}
	if (fullpath) {
		get_fullpath(fullpath, canonpathbuf, MAX_PATH);
		strcpy(canonpath, fullpath);
	}
	CANON_PATH_SIZE;
	if (fullsrcpath)
		strcpy(srccanonpath, fullsrcpath);
	SRC_CANON_PATH_SIZE;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_INDMAC;
        event.t_header.event_id = __NR_rename;
        event.flags = 0;
	event.mode = 0;
	event.isfirst = 0;
        ((header_token *)&event)->time.tv_sec = time.tv_sec;
        ((header_token *)&event)->time.tv_usec = time.tv_usec;
	AUDIT_GENERIC_WOTIME(2, event.filename_len + event.source_filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;     /* new path */
        WRITE_SRC_CANON_PATH; /* old path */
        SEND_DATA;
 bail:
	if (fullpath)
		kfree(fullpath);
        return returncode;
}

// Would like to audit reboots here.
// NOTE: this only audits when the reboot() system call is issued. There are
// many other ways to reboot a system (eg: kill -9 1) - this will NOT catch
// these.  In fact, a normal reboot from the gdm login manager (for example),
// does not seem to call the reboot() call. So this call may not be
// particularly useful.
// Only question is: does reboot return only after the system goes down?
// (in which case, I'll have to do the audit, fake the return code, and
// return with the orig_reboot().
// After all... we don't want to try and write stuff after filesystems have
// been unmounted.
static asmlinkage int
audit_reboot(int magic, int magic2, int flag, void *arg)
{
        int returncode;
        struct auditevent e;
        EVENT_SIZE(misc_class);

        returncode = orig_reboot(magic, magic2, flag, arg);
	if (!audit_process())
		goto bail;
        if (returncode < 0)
                goto bail;
        if (flag == LINUX_REBOOT_CMD_CAD_ON ||
            flag == LINUX_REBOOT_CMD_CAD_OFF) {
                return returncode;
        }
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_MISC;
        event.t_header.event_id = __NR_reboot;
        AUDIT_GENERIC(0, 0);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage long
audit_truncate(const char *pathname, unsigned long length)
{
        int returncode ;
        int audit_call = 1;
        struct auditevent e;
        int fd;
        struct file* f = NULL;
        DECLARE_INODE(iself);
        EVENT_SIZE(write1_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
	if (!audit_process())
		return(orig_truncate(pathname, length));
#ifdef VERSIONING
	update_version(pathname, (size_t)0, length, 1, "TV");
#endif /* VERSIONING */
        /* Replace truncate with open/ftruncate/close. */
        fd = audit_open(pathname, O_WRONLY, 0);
        if (fd < 0) {
                return fd;
        }

        event.t_header.event_class = AUDIT_CLASS_WRITE1;
        event.t_header.event_id = __NR_truncate;
        event.fd = fd;
        event.len = (unsigned int)length;
        event.data_len = event.pos = event.flags = 0;
        if (get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
                audit_call = 0;
                goto truncate_call;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
        
#ifdef SOLITUDE
        if (process_in_ifs() ||
            file_tainted_by_process_f(f, &event.i_nr, 1) == 0) {
                audit_call = 0;
        }
#endif /* SOLITUDE */
        fput(f);
 truncate_call:
        returncode = orig_ftruncate(fd, length);
        if(returncode < 0 || !audit_call)
                goto bail;
        event.t_header.ret = returncode;
        AUDIT_GENERIC(1, event.data_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
bail:
#ifdef SOLITUDE /* don't need to audit close with SOLITUDE */
        /* Do not use orig_close as auditing for close might be turned off*/
        sys_close(fd);
#else /* SOLITUDE */
        audit_close(fd);
#endif /* SOLITUDE */
        return returncode;
}

static asmlinkage int
audit_chdir(const char *pathname)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath = NULL;
	char fullpath[MAX_PATH];

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(chdir_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);

        returncode = orig_chdir(pathname);
	if (!audit_process())
		goto bail;
        if (returncode < 0)
                goto bail;
        canonpath = canonpathbuf;
        if (get_inode_path(pathname, &iself, &iparent, &canonpath, 
                           MAX_PATH)) {
                goto bail;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
                     iparent.i_igen, iparent.i_mode);
	if (copy_from_user(canonpathbuf, pathname, strnlen_user(pathname, MAX_PATH))) {
		returncode = -EFAULT;
		goto bail;
	}
	get_fullpath(fullpath, canonpathbuf, sizeof(fullpath));
	FULLPATH_SIZE;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CHDIR;
        event.t_header.event_id = __NR_chdir;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
	WRITE_FULLPATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_fchdir(int fd)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath = NULL;
        struct file* f = NULL;
        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(chdir_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);

        returncode = orig_fchdir(fd);
	if (!audit_process())
		goto bail;
        if (returncode < 0)
                goto bail;
        canonpath = canonpathbuf;
        if (get_inode_fd(&f, fd, &iself, &iparent, &canonpath, MAX_PATH, 
                          NULL)) {
                goto bail;
        }
        fput(f);
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen, 
                     iself.i_mode);
        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
                     iparent.i_igen, iparent.i_mode); 
        CANON_PATH_SIZE;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CHDIR;
        event.t_header.event_id = __NR_fchdir;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_chroot(const char *pathname)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;
        int audit_call = 1;
        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(chdir_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
	if (!audit_process())
		return orig_chroot(pathname);	
        canonpath = canonpathbuf;
        if (get_inode_path(pathname, &iself, &iparent, &canonpath, 
                           MAX_PATH)) {
                audit_call = 0;
                goto chroot_call;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
                     iparent.i_igen, iparent.i_mode);
        CANON_PATH_SIZE;
 chroot_call:
        returncode = orig_chroot(pathname);
        if (returncode < 0 || !audit_call)
                goto bail;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CHDIR;
        event.t_header.event_id = __NR_chroot;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;
        SEND_DATA;
 bail:
        return returncode;
}

/* Helper routine for auditing SU type syscalls */
static int
do_audit_ugid(int returncode, int syscall)
{
        struct auditevent e;
        EVENT_SIZE(setugid_class);
#ifdef SOLITUDE
        if (process_in_ifs() || !process_is_tainted()) {
                return 0;    
        }
#endif /* SOLITUDE */
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_SETUGID;
        event.t_header.event_id = syscall;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
        event.ruid = current_cred()->uid;
        event.euid = current_cred()->euid;
        event.suid = current_cred()->suid;
        event.rgid = current_cred()->gid;
        event.egid = current_cred()->egid;
        event.sgid = current_cred()->sgid;
#else
        event.ruid = current->uid;
        event.euid = current->euid;
        event.suid = current->suid;
        event.rgid = current->gid;
        event.egid = current->egid;
        event.sgid = current->sgid;
#endif
        AUDIT_GENERIC(0, 0);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
        return 0;
 bail:
        return 1;
}

static asmlinkage int
audit_setuid(uid_t uid)
{
        int returncode = orig_setuid(uid);
	if (!audit_process())
		return returncode;
        if (returncode >= 0)
                do_audit_ugid(returncode, __NR_setuid);
        return returncode;
}

static asmlinkage int
audit_setreuid(uid_t ruid, uid_t euid)
{
        int returncode = orig_setreuid(ruid, euid);
	if (!audit_process())
		return returncode;
        if (returncode >= 0)
                do_audit_ugid(returncode, __NR_setreuid);
        return returncode;
}

/* Set real, effective and saved user ID */
static asmlinkage int
audit_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
        int returncode = orig_setresuid(ruid, euid, suid);
	if (!audit_process())
		return returncode;
        if (returncode >= 0)
                do_audit_ugid(returncode, __NR_setresuid);
        return returncode;
}

static asmlinkage int
audit_setuid32(uid_t uid)
{
        int returncode = orig_setuid32(uid);
	if (!audit_process())
		return returncode;
        if (returncode >= 0)
                do_audit_ugid(returncode, __NR_setuid32);
        return returncode;
}

static asmlinkage int
audit_setreuid32(uid_t ruid, uid_t euid)
{
        int returncode = orig_setreuid32(ruid, euid);
        if (returncode >= 0)
                do_audit_ugid(returncode, __NR_setreuid32);
        return returncode;
}

static asmlinkage int
audit_setresuid32(uid_t ruid, uid_t euid, uid_t suid)
{
        int returncode = orig_setresuid32(ruid, euid, suid);
        if (returncode >= 0)        
                do_audit_ugid(returncode, __NR_setresuid32);
        return returncode;
}

static asmlinkage int
audit_setgid(gid_t gid)
{
        int returncode = orig_setgid(gid);
	if (!audit_process())
		return returncode;
        if (returncode >= 0)        
                do_audit_ugid(returncode, __NR_setgid);
        return returncode;
}

static asmlinkage int
audit_setregid(gid_t rgid, gid_t egid)
{
        int returncode = orig_setregid(rgid, egid);
	if (!audit_process())
		return returncode;
        if (returncode >= 0)        
                do_audit_ugid(returncode, __NR_setregid);
        return returncode;
}

static asmlinkage int
audit_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
        int returncode = orig_setresgid(rgid, egid, sgid);
	if (!audit_process())
		return returncode;
        if (returncode >= 0)        
                do_audit_ugid(returncode, __NR_setresgid);
        return returncode;
}

static asmlinkage int
audit_setgid32(gid_t gid)
{
        int returncode = orig_setgid32(gid);
	if (!audit_process())
		return returncode;
        if (returncode >= 0)        
                do_audit_ugid(returncode, __NR_setgid32);
        return returncode;
}

static asmlinkage int
audit_setregid32(gid_t rgid, gid_t egid)
{
        int returncode = orig_setregid32(rgid, egid);
	if (!audit_process())
		return returncode;
        if (returncode >= 0)        
                do_audit_ugid(returncode, __NR_setregid32);
        return returncode;
}

static asmlinkage int
audit_setresgid32(gid_t rgid, gid_t egid, gid_t sgid)
{
        int returncode = orig_setresgid32(rgid, egid, sgid);
	if (!audit_process())
		return returncode;
        if (returncode >= 0)        
                do_audit_ugid(returncode, __NR_setresgid32);
        return returncode;
}

/* Note that loff_t is assigned into a unsigned long for auditing. */
static asmlinkage long
audit_truncate64(const char *pathname, loff_t length)
{
        int returncode ;
        int audit_call = 1;
        struct auditevent e;
        int fd;
        struct file* f = NULL;
        DECLARE_INODE(iself);
        EVENT_SIZE(write1_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
	if (!audit_process())
		return (orig_truncate64(pathname, length));
        /* Replace truncate with open/ftruncate/close. */
        fd = audit_open(pathname, O_WRONLY, 0);
        if (fd < 0) {
                return fd;
        }

        event.t_header.event_class = AUDIT_CLASS_WRITE1;
        event.t_header.event_id = __NR_truncate64;
        event.fd = fd;
        event.len = (unsigned int)length;
        event.data_len = event.pos = event.flags = 0;
        if (get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
                audit_call = 0;
                goto truncate64_call;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                     iself.i_igen, iself.i_mode);
        
#ifdef SOLITUDE
        if (process_in_ifs() || 
            file_tainted_by_process_f(f, &event.i_nr, 1) == 0) {
                audit_call = 0;
        }
#endif /* SOLITUDE */
        fput(f);
 truncate64_call:
        returncode = orig_ftruncate64(fd, length);
        if (returncode < 0 || !audit_call)
                goto bail;
        event.t_header.ret = returncode;
        AUDIT_GENERIC(1, event.data_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
#ifdef SOLITUDE /* don't need to audit close with SOLITUDE */
        sys_close(fd);
#else /* SOLITUDE */
        audit_close(fd);
#endif /* SOLITUDE */
        return returncode;
}

#ifndef MAX_SOCK_ADDR
#define MAX_SOCK_ADDR 128 /* from net/socket.c */
#endif

static asmlinkage int
audit_send(int returncode, int fd, void __user *buff, size_t len,
           unsigned flags) {
        struct iovec iov;
        struct inode_nr inr;
        struct file* f = NULL;
        DECLARE_INODE(iself);
	SET_INODE_NR_SETSB(&inr, 0, 0, 0, 0, iself);

        if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
                SET_INODE_NR(&inr, iself.i_dev, iself.i_ino,
                        iself.i_igen, iself.i_mode);
                fput(f);
        }
        iov.iov_base = (void *)buff;
        iov.iov_len = len;
	return do_audit_write2_stream(returncode, fd, &iov, 1, SYS_SEND, flags,
                __NR_socketcall, &inr, NULL);
}

static asmlinkage int
audit_sendto(int returncode, int fd, void __user *buff, size_t len,
             unsigned flags, struct sockaddr __user *addr, int addr_len) {
        struct iovec iov;
        char addrbuf[MAX_SOCK_ADDR];
        struct sockaddr_in *toaddr;
        struct inode_nr inr;
        struct file* f = NULL;
        DECLARE_INODE(iself);
	SET_INODE_NR_SETSB(&inr, 0, 0, 0, 0, iself);

        if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
                SET_INODE_NR(&inr, iself.i_dev, iself.i_ino,
                        iself.i_igen, iself.i_mode);
                fput(f);
        }
        iov.iov_base = (void *)buff;
        iov.iov_len = len;

        /* Try to figure out the address if it is not provided. */
        if (addr) {
                if (copy_from_user(&addrbuf, addr, addr_len))
                        return 1;
                toaddr = (struct sockaddr_in *)addrbuf;
                /* Only capture IPv4 related traffic. */
                if (toaddr->sin_family != AF_INET)
                        return 0;

                return do_audit_write2(returncode, fd, &iov, 1, SYS_SENDTO,
                        flags, ntohl(toaddr->sin_addr.s_addr),
                        ntohs(toaddr->sin_port), __NR_socketcall, &inr, NULL);
        } else {
		return do_audit_write2_stream(returncode, fd, &iov, 1,
                        SYS_SENDTO, flags, __NR_socketcall, &inr, NULL);
        }
}

static asmlinkage int
audit_recv(int returncode, int fd, void __user *buff, size_t len,
           unsigned flags)
{
        struct inode_nr inr;
        struct file* f = NULL;
        DECLARE_INODE(iself);
        SET_INODE_NR_SETSB(&inr, 0, 0, 0, 0, iself);

        if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
                SET_INODE_NR(&inr, iself.i_dev, iself.i_ino,
                        iself.i_igen, iself.i_mode);
                fput(f);
        }
	return do_audit_read2_stream(returncode, fd, len, SYS_RECV, flags,
                __NR_socketcall, &inr, NULL);
}

static asmlinkage int
audit_recvfrom(int returncode, int fd, void __user *buff, size_t len,
               unsigned flags, struct sockaddr __user *addr,
               int __user *addr_len)
{
        char addrbuf[MAX_SOCK_ADDR];
        struct sockaddr_in *toaddr;
        int toaddr_len;
        struct inode_nr inr;
        struct file* f = NULL;
        DECLARE_INODE(iself);
        SET_INODE_NR_SETSB(&inr, 0, 0, 0, 0, iself);

        if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
                SET_INODE_NR(&inr, iself.i_dev, iself.i_ino,
                        iself.i_igen, iself.i_mode);
                fput(f);
        }

        /* Address and its length are guaranteed to be non-null. */
        if (copy_from_user(&toaddr_len, addr_len, sizeof(int)))
                return 1;
        if (copy_from_user(&addrbuf, addr, toaddr_len))
                return 1;
        toaddr = (struct sockaddr_in *)addrbuf;
        /* Only capture IPv4 related traffic. */
        if (toaddr->sin_family != AF_INET)
                return 0;

        return do_audit_read2(returncode, fd, len, SYS_RECVFROM,
                flags, ntohl(toaddr->sin_addr.s_addr),
                ntohs(toaddr->sin_port), __NR_socketcall, &inr, NULL);
}

/* Change this so we have an idea of what sort of socket is being opened. */
/* NOTE: report in the format 10.0.0.2:1234 (so match can look at ip and/or
   port!) */
static asmlinkage int
audit_socketcall(int call, unsigned long __user *args)
{
        int returncode;
        struct auditevent e;
        EVENT_SIZE(conn_class);
        struct sockaddr_in audit_in;
        unsigned long a[6];
        struct socket *sock;
        struct sock *sk;
        unsigned short sport;
        int err;
        struct file* f = NULL;
        DECLARE_INODE(iself);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
	if (!audit_process())
		return (orig_socketcall(call, args));
        switch (call) {
        case SYS_CONNECT:
        case SYS_ACCEPT:
                returncode = orig_socketcall(call, args);
                break;
        case SYS_SEND:
                returncode = orig_socketcall(call, args);
                if (copy_from_user(a, args, 4 * sizeof(unsigned long)))
                        return returncode;
                audit_send(returncode, a[0], (void *)a[1], a[2], a[3]);
                return returncode;
                break;
        case SYS_SENDTO:
                returncode = orig_socketcall(call, args);
                if (copy_from_user(a, args, 6 * sizeof(unsigned long)))
                        return returncode;
                audit_sendto(returncode, a[0], (void *)a[1], a[2], a[3],
                        (struct sockaddr __user *)a[4], a[5]);
                return returncode;
                break;
        case SYS_RECV:
                returncode = orig_socketcall(call, args);
                if (copy_from_user(a, args, 4 * sizeof(unsigned long)))
                        return returncode;
                audit_recv(returncode, a[0], (void *)a[1], a[2], a[3]);
                return returncode;
                break;
        case SYS_RECVFROM:
                if (copy_from_user(a, args, 6 * sizeof(unsigned long)))
                        return orig_socketcall(call, args);
                /* If the user app doesn't supply an addr and addr_len,
                 * use the last 20 bytes of the data buffer for it.
                 */
                if (!a[4]) {
                        a[2] -= sizeof(struct sockaddr_in) + sizeof(int);
                        a[4] = a[1] + a[2];
                        a[5] = a[4] + sizeof(struct sockaddr_in);
                        if (copy_to_user(&args[2], &a[2], sizeof(unsigned long)))
                                a[2] = 0;
                        if (copy_to_user(&args[4], &a[4], sizeof(unsigned long)))
                                a[4] = 0;
                        if (copy_to_user(&args[5], &a[5], sizeof(unsigned long)))
                                a[5] = 0;
                }
                returncode = orig_socketcall(call, args);
                audit_recvfrom(returncode, a[0], (void *)a[1], a[2], a[3],
                        (struct sockaddr __user *)a[4], (int __user *)a[5]);
                return returncode;
                break;
        default:
                return orig_socketcall(call, args);
                break;
        }

        do_gettimeofday(&event.t_header.time);

        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_CONN;
        event.t_header.event_id = __NR_socketcall;
        if (copy_from_user(a, args, 3 * sizeof(unsigned long)))
                return returncode;
        /* Currently we audit AF_INET calls only */
        if (copy_from_user(&audit_in, (struct sockaddr_in *)a[1],
                           sizeof(struct sockaddr_in)))
                return returncode;
        if (audit_in.sin_family != AF_INET)
                return returncode;
        sock = sockfd_lookup(a[0], &err);
        if (!sock)
                return returncode;
        sk = sock->sk;
	/* get local port */
	sport = ntohs(inet_sk(sk)->sport);
        sockfd_put(sock);
        event.call = call;
	event.fd = a[0];
        if (call == SYS_CONNECT) {
                if (returncode == 0 &&
                    !get_inode_fd(&f, a[0], &iself, NULL, NULL, 0,
                                  &event.t_header.time)) {
                        SET_INODE_NR(&(event.i_nr), iself.i_dev,
                                iself.i_ino, iself.i_igen, iself.i_mode);
                        fput(f);
                }
		event.source_ip = (127 << 24) + 1; /* 127.0.0.1 */
                event.source_port = sport;
		event.dest_ip = ntohl(audit_in.sin_addr.s_addr);
                event.dest_port = ntohs(audit_in.sin_port);
        } else if (call == SYS_ACCEPT) {
                event.t_header.time.tv_sec |= ISACCEPT_MASK;
                if (returncode >= 0 && 
                    !get_inode_fd(&f, returncode, &iself, NULL, NULL, 0,
                                  &event.t_header.time)) {
                        SET_INODE_NR(&(event.i_nr), iself.i_dev,
                                iself.i_ino, iself.i_igen, iself.i_mode);
                        fput(f);
                }
                event.i_nr.gen &= ~ISACCEPT_MASK;
                event.t_header.time.tv_sec &= ~ISACCEPT_MASK;
		event.source_ip = ntohl(audit_in.sin_addr.s_addr);
                event.source_port = ntohs(audit_in.sin_port);
		event.dest_ip = (127 << 24) + 1; /* 127.0.0.1 */
                event.dest_port = sport;
        }
        AUDIT_GENERIC_WOTIME(0, 0);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
        return returncode;
}

/* this call is gone from 2.6 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static asmlinkage unsigned long
audit_create_module(const char *name, size_t size)
{
        long returncode;
        struct auditevent e;
        EVENT_SIZE(module_class);
        MODNAME_SIZE;

        returncode = orig_create_module(name, size);
        if (returncode < 0)
                goto bail;
        event.t_header.ret = (returncode < 0 && returncode > -600) ? 
		returncode : 0;
        event.t_header.event_class = AUDIT_CLASS_MODULE;
        event.t_header.event_id = __NR_create_module;
        event.size = size;
        AUDIT_GENERIC(1, event.name_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_MODNAME;
        SEND_DATA;
 bail:
        return returncode;
}
#endif /* LINUX_VERSION_CODE */

/* TODO: this call takes completely different arguments in 2.6 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static asmlinkage unsigned long
audit_init_module(const char *name, struct module *image)
{
        long returncode;
        struct auditevent e;
        EVENT_SIZE(module_class);
        MODNAME_SIZE;

        returncode = orig_init_module(name, image);
        if (returncode < 0)
                goto bail;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_MODULE;
        event.t_header.event_id = __NR_init_module;
        event.size = 0;
        AUDIT_GENERIC(1, event.name_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_MODNAME;
        SEND_DATA;
 bail:
        return returncode;
}
#endif /* LINUX_VERSION_CODE */

static asmlinkage unsigned long
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
audit_delete_module(const char *name, unsigned int flags)
#else
audit_delete_module(const char *name)
#endif
{
        long returncode;
        struct auditevent e;
        EVENT_SIZE(module_class);
        MODNAME_SIZE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        returncode = orig_delete_module(name, flags);
#else
        returncode = orig_delete_module(name);
#endif
        if (returncode < 0)
                goto bail;
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_MODULE;
        event.t_header.event_id = __NR_delete_module;
        event.size = 0;
        AUDIT_GENERIC(1, event.name_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_MODNAME;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_mount(char *srcpath, char *pathname, char *type, unsigned long flags,
            void *data)
{
        int returncode;
        struct auditevent e;
        char canonpathbuf[MAX_PATH], srccanonpathbuf[MAX_PATH];
        char *canonpath, *srccanonpath;
        EVENT_SIZE(indmac_class);
        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        DECLARE_INODE(isrcparent);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//        SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);
//        SET_INODE_NR_SETSB(&(event.source_parent_i_nr), 0, 0, 0, 0, isrcparent);
//        event.owner = 0;
//        event.group = 0;

        returncode = orig_mount(srcpath, pathname, type, flags, data);
	if (!audit_process())
		goto bail;
        if (returncode < 0)
                goto bail;
        srccanonpath = srccanonpathbuf;
        if (get_inode_path(srcpath, NULL, &isrcparent, &srccanonpath,
                           MAX_PATH)) {
                goto bail;
        }
//        SET_INODE_NR(&(event.source_parent_i_nr), isrcparent.i_dev,
//                     isrcparent.i_ino, isrcparent.i_igen, isrcparent.i_mode);
        SRC_CANON_PATH_SIZE;

        event.t_header.ret = (int)returncode;
        event.t_header.event_class = AUDIT_CLASS_INDMAC;
        event.t_header.event_id = __NR_mount;

        canonpath = canonpathbuf;
        if (get_inode_path(pathname, &iself, &iparent, &canonpath, 
                           MAX_PATH)) {
                goto bail;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino, iself.i_igen,
                     iself.i_mode);
//        SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev, iparent.i_ino,
//                     iparent.i_igen, iparent.i_mode);
//        event.owner = iself.i_uid;
//        event.group = iself.i_gid;
        CANON_PATH_SIZE;
        event.flags = event.mode = event.isfirst = 0;
        AUDIT_GENERIC(2, event.filename_len + event.source_filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        WRITE_CANON_PATH;     /* dir_name */
        WRITE_SRC_CANON_PATH; /* dev_name */
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_umount(char *pathname, int flags)
{
        int returncode = 0;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;
        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(unlink_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
//	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);

        canonpath = canonpathbuf;
        if (!get_inode_path(pathname, &iself, &iparent, &canonpath,
                            MAX_PATH)) {
                SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                        iself.i_igen, iself.i_mode);
                SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev,
                        iparent.i_ino, iparent.i_igen, iparent.i_mode);
        } else {
                canonpath = NULL;
        }
        if (!canonpath || IS_ERR(canonpath)) {
                PATH_SIZE;
                canonpath = NULL;
        } else {
                CANON_PATH_SIZE;
        }
        returncode = orig_umount(pathname, flags);
	if (!audit_process())
		goto bail;
        if (returncode < 0)
                goto bail;
        event.t_header.ret = (int)returncode;
        event.t_header.event_class = AUDIT_CLASS_UNLINK;
        event.t_header.event_id = __NR_umount;
        event.islast = 0;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        if (canonpath) {
                WRITE_CANON_PATH;
        } else {
                WRITE_PATH;
        }
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_umount2(char *pathname, int flags)
{
        int returncode = 0;
        struct auditevent e;
        char canonpathbuf[MAX_PATH];
        char *canonpath;

        DECLARE_INODE(iself);
        DECLARE_INODE(iparent);
        EVENT_SIZE(unlink_class);
	SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
	SET_INODE_NR_SETSB(&(event.parent_i_nr), 0, 0, 0, 0, iparent);

        canonpath = canonpathbuf;
        if (!get_inode_path(pathname, &iself, &iparent, &canonpath,
                            MAX_PATH)) {
                SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                             iself.i_igen, iself.i_mode);
//                SET_INODE_NR(&(event.parent_i_nr), iparent.i_dev,
//                             iparent.i_ino, iparent.i_igen, iparent.i_mode);
        } else {
                canonpath = NULL;
        }
        if (!canonpath || IS_ERR(canonpath)) {
                PATH_SIZE;
                canonpath = NULL;
        } else {
                CANON_PATH_SIZE;
        }
        returncode = orig_umount2(pathname, flags);
	if (!audit_process())
		goto bail;
        if (returncode < 0)
                goto bail;
        event.t_header.ret = (int)returncode;
        event.t_header.event_class = AUDIT_CLASS_UNLINK;
        event.t_header.event_id = __NR_umount2;
        event.islast = 0;
        AUDIT_GENERIC(1, event.filename_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        if (canonpath) {
                WRITE_CANON_PATH;
        } else {
                WRITE_PATH;
        }
        SEND_DATA;
 bail:
        return returncode;
}

static inline int
do_audit_mmap(int returncode, int fd, unsigned long len, unsigned long pos,
	      unsigned long prot, int flags, int syscall)
{
        struct auditevent e;
        struct file* f = NULL;
        EVENT_SIZE(mmap_class);
        DECLARE_INODE(iself);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);

        if (!get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
                SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                        iself.i_igen, iself.i_mode);
                fput(f);
        }
        event.t_header.ret = (returncode < 0 && returncode > -600) ? 
		returncode : 0;
        event.t_header.event_class = AUDIT_CLASS_MMAP;
        event.t_header.event_id = syscall;
        event.fd = fd;
        event.prot = prot; /* overload with protections */
	event.offset = pos;
        event.flags = flags;
        event.len = len;
        AUDIT_GENERIC(0, 0);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
	return 0;
 bail:
        return 1;
}

struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};

static asmlinkage int
audit_mmap(void *arg)
{
	int returncode = orig_mmap(arg);
	struct mmap_arg_struct a;

	printad("%s\n", __FUNCTION__);
	if (!audit_process())
		goto bail;
        if (returncode < 0)
                return returncode;	
	if (copy_from_user(&a, arg, sizeof(a)))
		return returncode;
	if (a.flags & MAP_ANONYMOUS)
		a.fd = -1; /* fd is ignored */
	do_audit_mmap(returncode, a.fd, a.len, a.offset, a.prot,
                a.flags, __NR_mmap);
bail:
	return returncode;
}

static asmlinkage int
audit_mmap2(unsigned long addr, unsigned long len, unsigned long prot,
	    unsigned long flags, unsigned long fd, unsigned long pgoff)
{
	int returncode;

	printad("%s\n", __FUNCTION__);
	returncode  = orig_mmap2(addr, len, prot, flags, fd, pgoff);
	if (!audit_process())
		goto bail;
        //if (returncode < 0)
        //        return returncode;
	if (flags & MAP_ANONYMOUS)
		fd = -1; /* fd is ignored */
	do_audit_mmap(returncode, fd, len, pgoff << PAGE_SHIFT, prot, flags,
		      __NR_mmap2);
bail:
	return returncode;
}

static asmlinkage long
audit_munmap(unsigned long addr, size_t len)
{
	printad("%s\n", __FUNCTION__);
	return orig_munmap(addr, len);
}

static asmlinkage long
audit_ftruncate(unsigned int fd, unsigned long length)
{
        int returncode ;
        int audit_call = 1;     
        struct auditevent e;
        struct file* f = NULL;
	char pathname[MAX_PATH];
        EVENT_SIZE(write1_class);
        DECLARE_INODE(iself);
	DECLARE_INODE(iparent);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
	if (!audit_process()) {
		audit_call = 0;
		goto ftruncate_call;
	}
	if (!get_inode_fd(&f, fd, &iself, &iparent, NULL, 0, NULL)) {
		pathname[0] = '\0';
#ifdef VERSIONING
#ifdef VERSIONING_SNAPSHOT
		if (!get_name_from_node(iself.i_dev, iself.i_ino, iself.i_igen, pathname, sizeof(pathname), NULL)) {
#else /* VERSIONING_SNAPSHOT */
		if (!get_name_from_node(iself.i_dev, iself.i_ino, iself.i_igen, pathname, sizeof(pathname))) {
#endif /* VERSIONING */
			//printk("audit_ftruncate: pid(%d) read %s\n", current->pid, pathname);
			update_version(pathname, (size_t)0, length, 1, "TV");
		}
#endif /* VERSIONING */
               	fput(f);
        } 
	
        event.t_header.event_class = AUDIT_CLASS_WRITE1;
        event.t_header.event_id = __NR_ftruncate;
        event.fd = fd;
        event.len = (unsigned int)length;
        event.data_len = event.pos = event.flags = 0;
        if (get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
                audit_call = 0;
                goto ftruncate_call;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                     iself.i_igen, iself.i_mode);
        
#ifdef SOLITUDE
        if (process_in_ifs() || 
            file_tainted_by_process_f(f, &event.i_nr, 1) == 0) {
                audit_call = 0;
        }
#endif /* SOLITUDE */
        fput(f);
 ftruncate_call:       
        returncode = orig_ftruncate(fd, length);
        if (returncode < 0 || !audit_call)
                goto bail;
        event.t_header.ret = returncode;
        AUDIT_GENERIC(1, event.data_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage long
audit_ftruncate64(unsigned int fd, loff_t length)
{
        int returncode;
        int audit_call = 1;
        struct auditevent e;
        struct file* f = NULL;
        EVENT_SIZE(write1_class);
        DECLARE_INODE(iself);
        SET_INODE_NR_SETSB(&(event.i_nr), 0, 0, 0, 0, iself);
	if (!audit_process()) {
		audit_call = 0;
		goto ftruncate64_call;
	}
        event.t_header.event_class = AUDIT_CLASS_WRITE1;
        event.t_header.event_id = __NR_ftruncate64;
        event.fd = fd;
        event.len = (unsigned int)length;
        event.data_len = event.pos = event.flags = 0;
        if (get_inode_fd(&f, fd, &iself, NULL, NULL, 0, NULL)) {
                audit_call = 0;
                goto ftruncate64_call;
        }
        SET_INODE_NR(&(event.i_nr), iself.i_dev, iself.i_ino,
                     iself.i_igen, iself.i_mode);
        
#ifdef SOLITUDE
        if (process_in_ifs() || 
            file_tainted_by_process_f(f, &event.i_nr, 1) == 0) {
                audit_call = 0;
        }
#endif /* SOLITUDE */
        fput(f);
 ftruncate64_call:
        returncode = orig_ftruncate64(fd, length);
        if (returncode < 0 || !audit_call)
                goto bail;
        event.t_header.ret = returncode;        
        AUDIT_GENERIC(1, event.data_len);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
        return returncode;
}

#ifndef WIFEXITED
#define WIFEXITED(x) ((((__extension__ ({ union { __typeof(x) __in; \
int __i; } __u; __u.__in = (x); __u.__i; }))) & 0x7f) == 0)
#endif
#ifndef WEXITSTATUS
#define WEXITSTATUS(x) ((((__extension__ ({ union { __typeof(x) __in; \
int __i; } __u; __u.__in = (x); __u.__i; }))) & 0xff00) >> 8)
#endif
#ifndef WIFSIGNALED
#define WIFSIGNALED(x) (__extension__ ({ int __status = ((__extension__ ({ \
union { __typeof(x) __in; int __i; } __u; __u.__in = (x); __u.__i; }))); \
!(((__status) & 0xff) == 0x7f) && !(((__status) & 0x7f) == 0); }))
#endif
#ifndef WTERMSIG
#define WTERMSIG(x) (((__extension__ ({ union { __typeof(x) __in; \
int __i; } __u; __u.__in = (x); __u.__i; }))) & 0x7f)
#endif
#ifndef WIFSTOPPED
#define WIFSTOPPED(x) ((((__extension__ ({ union { __typeof(x) __in; \
int __i; } __u; __u.__in = (x); __u.__i; }))) & 0xff) == 0x7f)
#endif
#ifndef WSTOPSIG
#define WSTOPSIG(x) ((((__extension__ ({ union { __typeof(x) __in; \
int __i; } __u; __u.__in = (x); __u.__i; }))) & 0xff00) >> 8)
#endif

static asmlinkage int
audit_waitpid(int pid, int *status, int options)
{
	int returncode;
	struct auditevent e;
	mm_segment_t old_fs;
        EVENT_SIZE(signal_class);
	if (!audit_process())
		return orig_waitpid(pid, status, options);
	if(status) {
		returncode = orig_waitpid(pid, status, options);
                if (returncode < 0)
                        goto bail;
		if(copy_from_user(&event.sig, status, sizeof(int))) {
                        event.sig = 0;
                }
	} else {
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		returncode = orig_waitpid(pid, &event.sig, options);
		set_fs(old_fs);
	}
#ifdef SOLITUDE
        if (process_in_ifs())
                goto bail;
#endif /* SOLITUDE */
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_SIGNAL;
        event.t_header.event_id = __NR_waitpid;
        event.t_pid = pid;
        event.options = options;
        /* the child process (its pid is returncode) has already exited, so
           we can't get its start time. We set the t_pid_time to 1 below to
           tell the backend that this process has exited. The backend will
           figure out the start time. */
//        event.t_pid_time = 0;
        if (WIFEXITED(event.sig)) {
                event.status = WEXITSTATUS(event.sig);
                event.sig = 0;
//                event.t_pid_time = 1;
        } else if (WIFSIGNALED(event.sig)) {
                event.status = 0;
                event.sig = WTERMSIG(event.sig);
//                event.t_pid_time = 1;
        } else if (WIFSTOPPED(event.sig)) {
                event.status = 0;
                event.sig = WSTOPSIG(event.sig);
        }
        AUDIT_GENERIC(0, 0);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
        return returncode;
}

static asmlinkage int
audit_wait4(int pid, int * status, int options, struct rusage *rusage)
{
	int returncode;
	struct auditevent e;
	mm_segment_t old_fs;
        struct rusage krusage;
        EVENT_SIZE(signal_class);
	if (!audit_process())
		return orig_wait4(pid, status, options, rusage);
	if(status) {
		returncode = orig_wait4(pid, status, options, rusage);
                if (returncode < 0)
                        goto bail;
		ASSERT_AUDIT(!copy_from_user(&event.sig, status, sizeof(int)));
	} else if (rusage) {
                if (access_ok(VERIFY_READ, rusage, sizeof(struct rusage))) {
                        old_fs = get_fs();
                        set_fs(KERNEL_DS);
                        returncode =
                                orig_wait4(pid, &event.sig, options, &krusage);
        		set_fs(old_fs);
                        ASSERT_AUDIT(!copy_to_user
                                (rusage, &krusage, sizeof(struct rusage)));
                } else {
                        returncode = -EFAULT;
                        event.sig = 0;
                }
	} else {
                old_fs = get_fs();
                set_fs(KERNEL_DS);
                returncode = orig_wait4(pid, &event.sig, options, NULL);
		set_fs(old_fs);
        }

#ifdef SOLITUDE
        if (process_in_ifs())
                goto bail;
#endif /* SOLITUDE */
        event.t_header.ret = returncode;
        event.t_header.event_class = AUDIT_CLASS_SIGNAL;
        event.t_header.event_id = __NR_wait4;
        event.t_pid = pid;
        event.options = options;
        /* see comments in waitpid */
//        event.t_pid_time = 0;
        if (WIFEXITED(event.sig)) {
                event.status = WEXITSTATUS(event.sig);
                event.sig = 0;
//                event.t_pid_time = 1;
        } else if (WIFSIGNALED(event.sig)) {
                event.status = 0;
                event.sig = WTERMSIG(event.sig);
//                event.t_pid_time = 1;
        } else if (WIFSTOPPED(event.sig)) {
                event.status = 0;
                event.sig = WSTOPSIG(event.sig);
        }
        AUDIT_GENERIC(0, 0);
        AUDIT_ALLOC;
        WRITE_EVENT;
        SEND_DATA;
 bail:
        return returncode;
}


/***
 *** Section 8: Taint Propagation Policy
 ***/

#ifdef SOLITUDE

static int
check_if_in_ifs(struct file* f, const char* path)
{
        
        char* fullpath;
        ASSERT_AUDIT(f);
        ASSERT_AUDIT(path);
        
        fullpath = getname(path);
        
        if (IS_ERR(fullpath)) {
                printas("%s err %ld %s\n",
                        __FUNCTION__, PTR_ERR(fullpath), fullpath);
                return PTR_ERR(fullpath);
        }

        if (EXT3_I(f->f_dentry->d_inode)->i_flags & TESTBIT) {
                printk(KERN_INFO "DAMN test bit was one %s\n", fullpath);
        }


        
        if (strstr(fullpath, "__ifs")) {
                printk(KERN_INFO "%s IFS FOUND : %s\n", __FUNCTION__, fullpath);
                (f->f_dentry->d_inode)->i_flags |= IFSBIT;
                return 1;
        }
        
        putname(fullpath);
        return 0;
}


static int
get_fullnames(struct dentry *dentry, struct vfsmount *vfsmnt,
              struct inode* inode, int proc_by_file)
{
        
        char proc_name[TASK_COMM_LEN];
        char* fullpath;
        char fullpathbuf[MAX_PATH+11];
        *proc_name = '\0';
        *fullpathbuf = '\0';
        
        get_task_comm_copy(proc_name, current);
        fullpath = d_path(dentry, vfsmnt, fullpathbuf, MAX_PATH+11);
        if (IS_ERR(fullpath)) {
                printas("%s err %ld \n",
                        __FUNCTION__, PTR_ERR(fullpath));
                return PTR_ERR(fullpath);
        }
        if(proc_by_file)
        {
                printas("File %s inode %lo gen %d => pid %d:%s\n", fullpath, 
                        inode->i_ino, inode->i_generation, current->pid, 
                        proc_name);
        }
        else
        {
                if (strstr(fullpath, "__ifs")) {
                        printk(KERN_INFO "%s How did we get here? : %s\n", 
                               __FUNCTION__, fullpath);
                        (inode)->i_flags |= IFSBIT;
                        return 0;
                }
                else {
                        printas("pid %d:%s => File %s Inode %lo gen %d\n",
                                current->pid, proc_name, fullpath, inode->i_ino, 
                                inode->i_generation);
                        return 1;
                }
                
        }
        
        return 0;

}

static int
process_tainted_by_file_f(struct file* f)
{
        int ret;
        struct inode* inode = f->f_dentry->d_inode;
        ASSERT_AUDIT(inode);      
        /* If file is tainted, taint pid */
        if (file_is_tainted(inode)) {

                if ((ret = get_fullnames(f->f_dentry, f->f_vfsmnt, inode, 
                                         1)) < 0) {
                        return ret;
                }
                current->flags |= TAINTED_PROCESS_MASK;
                return 1;
        }
        // We dont need to log a process reading untainted files
        return 0;
}

static int
process_tainted_by_file_nd(struct nameidata nd)
{
        int ret;
        struct inode* inode = nd.dentry->d_inode;

        ASSERT_AUDIT(inode);      
        /* If file is tainted, taint pid */
        if (file_is_tainted(inode)) {

                if((ret = get_fullnames(nd.dentry, nd.mnt, inode, 1)) < 0)
                {
                        return ret;
                }
                current->flags |= TAINTED_PROCESS_MASK;
                return 1;
        }
        // We need to log tainted process execing untainted files
        return process_is_tainted();
}

static int
file_tainted_by_process_f(struct file* f,  struct inode_nr* inr, char send_orig)
{

        int ret;
        struct inode* inode = f->f_dentry->d_inode;

        ASSERT_AUDIT(inode);
        if(((inode->i_flags) & IFSBIT) == IFSBIT) {
                if(file_is_tainted(inode)){
                        printas("File in ifs is tainted!! HOSED !!\n");
                }
                return 0;
        }
        /* If pid is tainted, taint file */
        if(process_is_tainted() && file_is_untainted(inode)) {
                /* < is for err and = is for file_in_ifs case */
                if ((ret = get_fullnames(f->f_dentry, f->f_vfsmnt, inode,
                                         0))<= 0) {
                        return ret;
                }
                EXT3_I(inode)->i_flags |= TAINTED_FILE_MASK;
                if ((inode->i_state & I_DIRTY) != I_DIRTY){
                	mark_inode_dirty(inode);
                }
                /* send_original_file only when fd >= 0 or path is
                 * non-NULL. Also send regular files only. */
                if (send_orig && S_ISREG(inode->i_mode))
                {
                        printas("file_len %d\n", 
                               (int)inode->i_size );
                        send_original_file(f, inode->i_size, *inr);
                }
        }
        /* If file is tainted, send call */
        return file_is_tainted(inode);
}

static int
file_tainted_by_process_nd(const char* path, struct inode_nr* inr, 
                           char send_orig)
{
        int ret = 0;
        struct file* f;
        char *fullpath;
        ASSERT_AUDIT(path);
        fullpath = getname(path);
        
        if (IS_ERR(fullpath)) {
                printas("%s getname err %ld %s\n",
                       __FUNCTION__, PTR_ERR(fullpath), fullpath);
                return PTR_ERR(fullpath);
        }
        f = filp_open(fullpath, O_RDONLY | O_NONBLOCK, 0);
        if (IS_ERR(f)) {
                printas("%s filp_open err %ld %s\n",
                       __FUNCTION__, PTR_ERR(f), fullpath);
                putname(fullpath);
                return PTR_ERR(f);
        }
        if (strstr(fullpath, "__ifs")) {
                printk(KERN_INFO "%s IFS FOUND : %s\n", __FUNCTION__, fullpath);
                (f->f_dentry->d_inode)->i_flags |= IFSBIT;
        }
        ret =  file_tainted_by_process_f(f, inr, send_orig);
        if (ret == 1) {
                printas("%s File was tainted: %s\n", __FUNCTION__, fullpath);
        }
        filp_close(f, current->files);
        putname(fullpath);
        return ret;
}

#ifdef SOLITUDE_CAPABILITIES
#include <linux/hash.h>

/* don't need to reference count this structure because we assume that
 * there is only one such structure per process. */
struct ifs_task {
        struct hlist_node hash;
        int pid;
        struct ifs_capability_set *cap_set;
};

/* this lock protects the ifs_task struct for all tasks */
static DEFINE_SPINLOCK(ifs_task_lock);

#define PIDHASH_SHIFT 6
#define HASHSIZE 1 << PIDHASH_SHIFT
#define pid_hashfn(nr) hash_long((unsigned long)nr, PIDHASH_SHIFT)

static struct hlist_head hash_list[HASHSIZE];

static struct ifs_task *
ifs_task_find(int pid)
{
        struct hlist_head *hh = hash_list + pid_hashfn(pid);
        struct hlist_node *hn;
        struct ifs_task *c = NULL;

        hlist_for_each_entry(c, hn, hh, hash) {
                if (c->pid == pid) {
                        break;
                }
        }
        return c;
}

/* call with spin_lock held */
static void
ifs_capability_set_get(struct ifs_capability_set *cap_set)
{
        ASSERT_AUDIT(cap_set);
        cap_set->count++;
}

/* call with spin_lock held, releases spin_lock */
static void
ifs_capability_set_put(struct ifs_capability_set *cap_set)
{
        int free_cap_set = 0;

        ASSERT_AUDIT(cap_set);
        if (--cap_set->count == 0) {
                free_cap_set = 1;
        }
        spin_unlock(&ifs_task_lock);

        if (free_cap_set) kfree(cap_set);
}

static void
ifs_task_destroy(struct ifs_task *it)
{
        ASSERT_AUDIT(hlist_unhashed(&it->hash) == 0);
        hlist_del(&it->hash);
        ifs_capability_set_put(it->cap_set);
        kfree(it);
}

/* acquires spin_lock */
static struct ifs_task *
ifs_task_alloc(int pid)
{
        struct ifs_task *it, *pit;

        it = kmalloc(sizeof(struct ifs_task), GFP_KERNEL);
        if (!it)
                return NULL;
        INIT_HLIST_NODE(&it->hash);
        it->pid = pid;
        it->cap_set = NULL;
restart:
        spin_lock(&ifs_task_lock);
        if ((pit = ifs_task_find(pid))) { /* stale ifs_task */
                ifs_task_destroy(pit);
                goto restart;
        }
        hlist_add_head(&it->hash, hash_list + pid_hashfn(pid));
        return it;
}

static int
ifs_start(struct ifs_capability_set __user *ucap_set)
{
        struct ifs_task *it;
        struct ifs_capability_set *cap_set;
        int nr_cap = 0;
        
        if (ucap_set) {
                if (copy_from_user(&nr_cap, ucap_set, sizeof(int)))
                        return -EFAULT;
        } else {
                nr_cap = 0;
        }

        /* allocate all capabilities after ifs_capability_set struct */
        cap_set = kcalloc(1, sizeof(struct ifs_capability_set) + 
                          nr_cap * sizeof(struct ifs_capability), GFP_KERNEL);
        cap_set->nr_cap = nr_cap;
        cap_set->count = 1;
        cap_set->cap = (struct ifs_capability *)
                ((char *)cap_set + sizeof(struct ifs_capability_set));
        /* now copy the capabilities */
        if (ucap_set && copy_from_user(cap_set->cap, (char *)ucap_set +
                                       sizeof(struct ifs_capability_set), 
                                       nr_cap * sizeof(struct ifs_capability))) {
                kfree(cap_set);
                return -EFAULT;
        }
        /* setup ifs_task */
        it = ifs_task_alloc(current->pid);
        if (!it) {
                ifs_capability_set_put(cap_set);
                return -ENOMEM;
        }
        it->cap_set = cap_set;
        spin_unlock(&ifs_task_lock);
        return 0;
}

static int
ifs_fork(int child_pid)
{
        struct ifs_task *pit, *cit;
        struct ifs_capability_set *cap_set;

        ASSERT_AUDIT(child_pid != current->pid);

        spin_lock(&ifs_task_lock);
        pit = ifs_task_find(current->pid);
        if (!pit) { /* parent has no task structure */
                printk("%s: no capability parent: pid = %d, child_pid = %d\n",
                       __FUNCTION__, current->pid, child_pid);
                spin_unlock(&ifs_task_lock);
                return 0;
        }
        cap_set = pit->cap_set;
        ifs_capability_set_get(cap_set);
        spin_unlock(&ifs_task_lock);

        cit = ifs_task_alloc(child_pid);
        if (!cit) {
                ifs_capability_set_put(cap_set);
                return -ENOMEM;
        }
        cit->cap_set = cap_set;
        spin_unlock(&ifs_task_lock);
        return 0;
}

static void
ifs_execve(void)
{
        struct ifs_task *it;
        int nr_cap;

        spin_lock(&ifs_task_lock);
        it = ifs_task_find(current->pid);
        if (!it) {
                printk("%s: no capability process: pid = %d\n", __FUNCTION__,
                       current->pid);
                spin_unlock(&ifs_task_lock);
                return;
        }
        ASSERT_AUDIT(it->cap_set);
        ASSERT_AUDIT(it->cap_set->count > 0);
        nr_cap = it->cap_set->nr_cap;
        /* TODO: set capabilities */
        // look if we have a capability assigned for executable
        if(execs are equal) {
                current->cap_effective = orig_cap_effective;
                current->cap_inheritable = orig_cap_inheritable;
                current->cap_permitted = orig_cap_permitted;
        }
        
        spin_unlock(&ifs_task_lock);
        /* debugging */
        printk("pid = %d: nr of cap = %d\n", current->pid, nr_cap);
}

#else /* SOLITUDE_CAPABILITIES */

static int
ifs_start(struct ifs_capability_set __user *ucap_set)
{
        return 0;
}
static int
ifs_fork(int child_pid)
{
        return 0;
}
static void
ifs_execve(void)
{
}
#endif /* SOLITUDE_CAPABILITIES */
#endif /* SOLITUDE */

/* this is a copy of a kernel routine */
static void
get_task_comm_copy(char *buf, struct task_struct *tsk)
{
	/* buf must be at least sizeof(tsk->comm) in size */
	buf[0] = '\0';
	task_lock(tsk);
	strncpy(buf, tsk->comm, sizeof(tsk->comm));
	task_unlock(tsk);
	buf[sizeof(tsk->comm) - 1] = '\0';
}

#define DIFF_FILES_BUF_SIZE 512

/*
 * Compare the content of two files
 * Returns	0	contents are the same
 *		1	contents are different
 *		2	sizes are different
 *		-1	error
 * Note: it has to be invoked in the context of a process
 *	 srcpath and destpath must be in kernel space
 *       orig_stat, orig_open, orig_read, orig_close must be set
 */	
int diff_files(const char *srcpath, const char *destpath)
{
	int srcfd, destfd;
	char *buf = NULL;
	int ret = 0;
	struct stat stbuf;
	off_t srclen = -1, destlen = -1;
	int read_size;
	char srcunlinkpath[MAX_PATH];
	mm_segment_t old_fs;
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	if (orig_stat(srcpath, &stbuf) == 0)
		srclen = stbuf.st_size;
	else {
		sprintf(srcunlinkpath, "%s.unlink", srcpath);
		srcpath = srcunlinkpath;
		if (orig_stat(srcpath, &stbuf) == 0)
			srclen = stbuf.st_size;
	}
	if (orig_stat(destpath, &stbuf) == 0)
		destlen = stbuf.st_size;
	printk("diff_files [%s] [%s]\n", srcpath, destpath);
	if (srclen == 0 && destlen == 0)
		goto out;
	if (!(srclen > 0 && destlen > 0 && srclen == destlen)) {
		printk("diff_files [%s](%ld) [%s](%ld)\n", srcpath, srclen, destpath, destlen);
		ret = 2;
		goto out;
	}
	srcfd = orig_open(srcpath, O_RDONLY, 0400);
	if (srcfd == -1) {
		printk("diff_files can't open src:%s\n", srcpath);
		ret = -1;
		goto out;
	}
	destfd = orig_open(destpath, O_RDONLY, 0400);
	if (destfd == -1) {
		orig_close(srcfd);
		printk("diff_files can't open dest:%s\n", destpath);
		ret = -1;
		goto out;
	}
	buf = (char *)kmalloc(DIFF_FILES_BUF_SIZE * 2, GFP_KERNEL);
	if (buf != NULL) {
		do {
			read_size = orig_read(srcfd, buf, DIFF_FILES_BUF_SIZE);
			if (read_size <= 0)
				break;
			read_size = orig_read(destfd, buf + DIFF_FILES_BUF_SIZE, DIFF_FILES_BUF_SIZE);
			if (read_size <= 0)
				break;
			if (memcmp(buf, buf + DIFF_FILES_BUF_SIZE, read_size)) {
				ret = 1;
				break;
			}
		
		} while (read_size > 0);
		if (read_size < 0) {
			printk("diff_files read file error\n");
			ret = -1;
		}
		kfree(buf);
	} else {
		printk("diff_files kmalloc failed\n");
		ret = -1;
	}
	orig_close(srcfd);
	orig_close(destfd);
out:
	set_fs(old_fs);
	printk("diff_files [%s] [%s] ret:%d\n", srcpath, destpath, ret);
	return ret;
}

/*
 * allocate a kernel buffer and read the content from file srcpath (kernel space string)
 * returns the pointer to the buffer when succeeds
 */
char *read_whole_file(const char *srcpath, int *file_data_len)
{
	int srcfd = -1;
	char *buf = NULL;
	struct stat stbuf;
	unsigned int srclen = 0;
	int read_size = 0;
	mm_segment_t old_fs;
	int ret;

	printk("read_whole_file %s\n", srcpath);	

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = orig_stat(srcpath, &stbuf);
	set_fs(old_fs);
	if (ret == 0)
		srclen = stbuf.st_size;
	else
		printk("read_whole_file stat file failed\n");
	if (srclen == 0)
		goto out;
	buf = (char *)kmalloc(srclen, GFP_KERNEL);
	if (buf != NULL) {
		set_fs(KERNEL_DS);
		srcfd = orig_open(srcpath, O_RDONLY, 0400);
		if (srcfd >= 0) {
			read_size = orig_read(srcfd, buf, srclen);
			orig_close(srcfd);
		}
		set_fs(old_fs);
		if (srcfd == -1)
			printk("read_whole_file open file failed\n");
		if (read_size > 0)
			*file_data_len = read_size;
		else if (read_size < 0)
			printk("read_whole_file read file %s error\n", srcpath);
	} else
		printk("read_whole_file kmalloc %d bytes failed\n", srclen);
out:
	return buf;
}

#ifdef SAVE_FILE_DATA

/*
 * create absolute directory
 *       dirname is in kernel space
 * Note: should not be called outside create_absolute_path
 */
static int
create_absolute_directory(const char *dirname, int mode)
{
	struct stat stbuf;
	char *dirend = NULL;
	int ret = 0;

	if (orig_stat(dirname, &stbuf)==0) {
		goto out;
	}
	if (*dirname == '/')
		dirend = strchr(dirname + 1, '/');
	else
		dirend = strchr(dirname, '/');
	while (dirend != NULL) {
		*dirend = '\0';
		if (orig_stat(dirname, &stbuf) != 0) {
			//printk("mkdir %s\n", dirname);
			ret = orig_mkdir(dirname, mode);
			if (ret != 0)
				printk("pid:%d mkdir %s failed %d\n", current->pid, dirname, ret);
		}
		*dirend = '/';
		if (ret != 0 ) {
			break;
		}
		dirend = strchr(dirend + 1, '/');
	}
	if (ret == 0) {
		if (orig_stat(dirname, &stbuf) != 0) {
			//printk("mkdir %s\n", dirname);
			ret = orig_mkdir(dirname, mode);
			if (ret != 0)
				printk("pid:%d mkdir %s failed %d\n", current->pid, dirname, ret);
		}
	}
out:
	return ret;
}

/*
 * create absolute path
 *	pathname is in kernel space
 * Note: set_fs(KERNEL_DS) has to be called before calling this function
 */
static int
create_absolute_path(const char *pathname)
{
	char *dirend = NULL;
	char *dirname = NULL;
	int ret = 0;

	//printk("%s pid:%d %s\n", __FUNCTION__, current->pid, pathname);
	dirname = kmalloc(MAX_PATH, GFP_KERNEL);
	if (dirname != NULL) {
		strncpy(dirname, pathname, MAX_PATH);
		dirend = strrchr(dirname, '/');
		if (dirend != NULL) {
			*dirend = '\0';
			ret = create_absolute_directory(dirname, 0777);
			//printk("%s pid:%d %s returns %d\n", __FUNCTION__, current->pid, pathname, ret);
		}
		kfree(dirname);
	} else {
		ret = -1;
		printk("%s pid:%d failed to allocate %d bytes memory\n", __FUNCTION__, current->pid, MAX_PATH);
	}
	return ret;
}

int file_read(struct file *file, loff_t *pos, char *buf, size_t count)
{
	int ret;

	ret = file->f_op->read(file, buf, count, pos);
	file->f_pos = *pos;
	return ret;
}

int file_write(struct file *file, loff_t *pos, const char *buf, size_t count)
{
	int ret;

	ret = file->f_op->write(file, buf, count, pos);
	file->f_pos = *pos;
	return ret;
}

int file_lseek(struct file *file, loff_t pos)
{
	if (file->f_pos != pos)
		file->f_pos = pos;
	return pos;
}

int write_dat_header(struct file *file, loff_t* pos)
{
	static struct dat_header header;
	static int first = 1;

	if (first) {
		memcpy(header.flag, TRACE_DAT_FLAG, TRACE_DAT_FLAG_LEN);
		header.major = TRACE_DAT_MAJOR;
		header.minor = TRACE_DAT_MINOR;
		header.rec_size = sizeof(struct dat_entry);
		first = 0;
	}
	return file_write(file, pos, (const char *)&header, sizeof(header));
}

int write_src_data(struct file *file, loff_t *pos, struct file *srcfile, const char *srcpath, size_t file_size)
{
	int ret = 0;
	size_t write_size = 0;
	struct page *pg = NULL;
	char *buf = NULL;
	loff_t read_pos;

	pg = alloc_pages(GFP_KERNEL, 0);
	if (pg == NULL) {
		printk("%s out of memory\n", __FUNCTION__);
		ret = -1;
		goto out;
	}
	buf = page_address(pg);
	write_size = 0;
	read_pos = 0;
	while (write_size < file_size) {
		ret = file_read(srcfile, &read_pos, buf, (file_size - write_size > PAGE_SIZE ? PAGE_SIZE : file_size - write_size));
		if (ret > 0) {
			ret = file_write(auditdata.datafp, pos, buf, ret);
			if (ret > 0)
				write_size += ret;
			else {
				printk("%s:%s pid:%d write file error %d\n", __FUNCTION__, srcpath, current->pid, ret);
				break;
			}
		} else {
			if (ret < 0) 
				printk("%s:%s pid:%d read file error %d\n",__FUNCTION__, srcpath, current->pid, ret);
			break;
		}
	}
	if (ret >= 0)
		ret = write_size;
        __free_page(pg);
out:
	return ret;
}

int write_dat_entry_ex(struct file *file, loff_t *pos, const char *srcpath, size_t file_size, int seq_no)
{
	struct dat_entry entry;
	int ret;

	entry.pid = current->pid;
   	do_gettimeofday(&entry.time);
	entry.path_len = strlen(srcpath);
	entry.file_size = file_size;
	entry.seq_no = seq_no;
	ret = file_write(file, pos, (const char *)&entry, sizeof(entry));
	if (ret < 0) {
		printk("%s:%s pid:%d write entry error %d\n", __FUNCTION__, srcpath, current->pid, ret);
	}
	return ret;
}

int write_dat_entry(struct file *file, loff_t *pos, struct file *srcfile, const char *srcpath, size_t file_size, int seq_no)
{
	int ret;
	loff_t entry_pos, next_entry_pos;

	entry_pos = *pos;
	ret = write_dat_entry_ex(file, pos, srcpath, file_size, seq_no);
	if (ret < 0)
		goto out;
	ret = file_write(file, pos, srcpath, strlen(srcpath));
	if (ret < 0) {
		printk("%s:%s pid:%d write srcpath error %d\n", __FUNCTION__, srcpath, current->pid, ret);
		goto out;
	}
	ret = write_src_data(file, pos, srcfile, srcpath, file_size);
	if (ret >= 0) {
		if (ret != file_size) {
			printk("%s:%s pid:%d write_size:%d file_size:%d\n", __FUNCTION__, srcpath, current->pid, (int)ret, (int)file_size);
			next_entry_pos = *pos;
			*pos = entry_pos;
			ret = write_dat_entry_ex(file, pos, srcpath, ret, seq_no);
			*pos = next_entry_pos;
			file_lseek(file, *pos);
		}
	} else {
		file_lseek(file, entry_pos);
	}
out:
	return ret;
}

int copy_data_from_file(const char *srcpath, size_t file_size)
{
	loff_t dat_offset = 0;
	mm_segment_t old_fs;
	struct file *srcfile = NULL;
	int ret = 0;

	srcfile = filp_open(srcpath, O_RDONLY|O_NONBLOCK, 0);
	if (srcfile == NULL || IS_ERR(srcfile)) {
		if (IS_ERR(srcfile)) {
		        ret = PTR_ERR(srcfile);
			printk("%s open %s failed %d\n", __FUNCTION__, srcpath, ret);
		}
		goto out;
	}
	ret = 0;
	dat_offset = auditdata.datafp->f_pos;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	if (dat_offset == 0) {
		ret = write_dat_header(auditdata.datafp, &dat_offset);
		if (ret < 0) {
			printk("%s:%s pid:%d write header error:%d\n", __FUNCTION__, srcpath, current->pid, ret);
			goto write_done;
		}
	}
	ret = write_dat_entry(auditdata.datafp, &dat_offset, srcfile, srcpath, file_size, auditdata.dataseq);
	if (ret >= 0)
		auditdata.dataseq++;
write_done:
	set_fs(old_fs);
	filp_close(srcfile, NULL);
out:
	return ret;
}

// Maximum file size to copy
// set to 100MB

#define MAX_DAT_ENTRY_SIZE 104857600

/*
 * save the content of srcpath file
 * srcpath is in kernel space
 */
static int 
save_file(const char *srcpath)
{
	mm_segment_t old_fs;
	int ret = -1;
	int shadowfd = -1;
	int err;
        char shadowpathbuf[MAX_PATH];
	size_t file_size = 0;
	long filemode = 0777;
	long oldmask;
	struct nameidata nd;
	//struct dentry *dentry = NULL;
	//struct inode *inode = NULL;
	//umode_t i_mode;

	down(&save_file_lock);
	// prevent recursively save file
	if (strlen(srcpath) > auditdata.shadow_dir_len) {
		 if (strncmp(srcpath, auditdata.shadow_dir, auditdata.shadow_dir_len) == 0) {
			printk("pid:%d save_file on file %s in shadow directory!\n", current->pid, srcpath);
			goto out;
		}
	}
	if (*srcpath == '/')
		snprintf(shadowpathbuf, sizeof(shadowpathbuf), "%s%s", auditdata.shadow_dir, srcpath);
	else
		snprintf(shadowpathbuf, sizeof(shadowpathbuf), "%s/%s", auditdata.shadow_dir, srcpath);

	// check if file is already saved
	ret = path_lookup(shadowpathbuf, LOOKUP_FOLLOW, &nd);
	if (ret == 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
		path_put(&nd.path);
#else
		path_release(&nd);
#endif
		goto out;
	}

// log the list of shadow files for debugging
#if 1
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	shadowfd = orig_open("/etc/ocasta/.dir/files.log", O_WRONLY|O_CREAT|O_APPEND|O_NONBLOCK, filemode);
	if (shadowfd >= 0) {
		orig_write(shadowfd, auditdata.data_file_name, strlen(auditdata.data_file_name));
		orig_write(shadowfd, STR_COLON, strlen(STR_COLON));
		orig_write(shadowfd, srcpath, strlen(srcpath));
		orig_write(shadowfd, STR_LINEFEED, strlen(STR_LINEFEED));
		orig_close(shadowfd);
	}
	set_fs(old_fs);
#endif
	old_fs = get_fs();
	set_fs(get_ds());
	if (is_regfile(srcpath, &file_size) && file_size < MAX_DAT_ENTRY_SIZE)
		copy_data_from_file(srcpath, file_size);
	// mark that we saved the file
	oldmask = orig_umask(0);
	if (create_absolute_path(shadowpathbuf) == 0) {
#if 0
		shadowfd = orig_open(shadowpathbuf, O_CREAT|O_NONBLOCK, filemode);
		if (shadowfd < 0)
			printk("%s failed to create shadow:%s(%d)\n", __FUNCTION__, shadowpathbuf, shadowfd);
		else
			orig_close(shadowfd);
#else
		err = orig_mknod(shadowpathbuf, 0666|S_IFREG, 0);
		if (err != 0)
			printk("%s failed to create shadow:%s(%d)\n", __FUNCTION__, shadowpathbuf, err);
#endif
	}
	set_fs(old_fs);
	orig_umask(oldmask);
out:
	up(&save_file_lock);
	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
/*
 * This code is only intended to run on x86 platforms
 * not used to unset page attribute
 */
static int __change_page_attr(struct page* page, pgprot_t prot)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	unsigned int level;
#else
	struct page *kpte_page;
#endif
	unsigned long address;
	pte_t *kpte, old_pte;
	int ret = 0;

	address = (unsigned long)page_address(page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	kpte = lookup_address_fn(address, &level);
#else
	kpte = lookup_address_fn(address);
#endif
	if (!kpte) {
		ret = -EFAULT;
		goto out;
	}
	old_pte = *kpte;
	if (!pte_val(old_pte)) {
		ret = -EINVAL;
		printk("change_page_attr %lx=>%p\n", address, kpte);
		goto out;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	if (level == PG_LEVEL_4K) {
		pte_t new_pte;
		pgprot_t new_prot = pte_pgprot(old_pte);
		unsigned long pfn = pte_pfn(old_pte);

		pgprot_val(new_prot) |= pgprot_val(prot);
		new_pte = pfn_pte(pfn, canon_pgprot(new_prot));
		if (pte_val(old_pte) != pte_val(new_pte))
			set_pte_atomic(kpte, new_pte);
#else
	kpte_page = virt_to_page(kpte);
	if (!pte_huge(*kpte)) {
		if (pgprot_val(prot) != pgprot_val(PAGE_KERNEL))
			set_pte_atomic(kpte, mk_pte(page, prot));
		else
			set_pte_atomic(kpte, mk_pte(page, PAGE_KERNEL));
		page_private(kpte_page)++;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	} else {
		printk("%s: level=%d kpte=%p addr=%lx\n", __FUNCTION__, level, kpte, address);
		ret = -EINVAL;
	}
#else
	} else
		ret = -EINVAL;
#endif
out:
	return ret;
}

/*
 * This code replaces the kernel function change_page_attr()
 * in order to circulmvent the check in some kernel to prevent setting PAGE_RW 
 * attribute for any .rodata page.
 */
static int change_page_attr_ex(struct page *page, int numpages, pgprot_t prot)
{
	int i, ret;
	unsigned long flags;

	local_irq_save(flags);
	for (i = 0; i < numpages; i++, page++) {
		ret = __change_page_attr(page, prot);
		if (ret != 0)
			break;
	}
	local_irq_restore(flags);
	return ret;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
struct cpa_data {
        unsigned long   vaddr;
        pgprot_t        mask_set;
        pgprot_t        mask_clr;
        int             numpages;
        int             flushtlb;
        unsigned long   pfn;
        unsigned        force_split : 1;
};

static void __set_pmd_pte(pte_t *kpte, unsigned long address, pte_t pte)
{
	/* change init_mm */
	set_pte_atomic(kpte, pte);
}

static inline int cache_attr(pgprot_t attr)
{
	return pgprot_val(attr) &
		(_PAGE_PAT | _PAGE_PAT_LARGE | _PAGE_PWT | _PAGE_PCD);
}

static int split_large_page(pte_t *kpte, unsigned long address)
{
	printk(KERN_WARNING "split_large_page");
	return 0;
}

static int
try_preserve_large_page(pte_t *kpte, unsigned long address,
			struct cpa_data *cpa)
{
	unsigned long nextpage_addr, numpages, pmask, psize, flags, addr, pfn;
	pte_t new_pte, old_pte, *tmp;
	pgprot_t old_prot, new_prot;
	int i, do_split = 1;
	unsigned int level;

	if (cpa->force_split)
		return 1;

	local_irq_save(flags); 	//spin_lock_irqsave(&pgd_lock, flags);
	/*
	 * Check for races, another CPU might have split this page
	 * up already:
	 */
	tmp = lookup_address_fn(address, &level);
	if (tmp != kpte)
		goto out_unlock;

	switch (level) {
	case PG_LEVEL_2M:
		psize = PMD_PAGE_SIZE;
		pmask = PMD_PAGE_MASK;
		break;
#ifdef CONFIG_X86_64
	case PG_LEVEL_1G:
		psize = PUD_PAGE_SIZE;
		pmask = PUD_PAGE_MASK;
		break;
#endif
	default:
		do_split = -EINVAL;
		goto out_unlock;
	}

	/*
	 * Calculate the number of pages, which fit into this large
	 * page starting at address:
	 */
	nextpage_addr = (address + psize) & pmask;
	numpages = (nextpage_addr - address) >> PAGE_SHIFT;
	if (numpages < cpa->numpages)
		cpa->numpages = numpages;

	/*
	 * We are safe now. Check whether the new pgprot is the same:
	 */
	old_pte = *kpte;
	old_prot = new_prot = pte_pgprot(old_pte);

	pgprot_val(new_prot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(new_prot) |= pgprot_val(cpa->mask_set);

	/*
	 * old_pte points to the large page base address. So we need
	 * to add the offset of the virtual address:
	 */
	pfn = pte_pfn(old_pte) + ((address & (psize - 1)) >> PAGE_SHIFT);
	cpa->pfn = pfn;

	//new_prot = static_protections(new_prot, address, pfn);

	/*
	 * We need to check the full range, whether
	 * static_protection() requires a different pgprot for one of
	 * the pages in the range we try to preserve:
	 */
	addr = address + PAGE_SIZE;
	pfn++;
	for (i = 1; i < cpa->numpages; i++, addr += PAGE_SIZE, pfn++) {
		//pgprot_t chk_prot = static_protections(new_prot, addr, pfn);
		pgprot_t chk_prot = new_prot;

		if (pgprot_val(chk_prot) != pgprot_val(new_prot))
			goto out_unlock;
	}

	/*
	 * If there are no changes, return. maxpages has been updated
	 * above:
	 */
	if (pgprot_val(new_prot) == pgprot_val(old_prot)) {
		do_split = 0;
		goto out_unlock;
	}

	/*
	 * We need to change the attributes. Check, whether we can
	 * change the large page in one go. We request a split, when
	 * the address is not aligned and the number of pages is
	 * smaller than the number of pages in the large page. Note
	 * that we limited the number of possible pages already to
	 * the number of pages in the large page.
	 */
	if (address == (nextpage_addr - psize) && cpa->numpages == numpages) {
		/*
		 * The address is aligned and the number of pages
		 * covers the full page.
		 */
		new_pte = pfn_pte(pte_pfn(old_pte), canon_pgprot(new_prot));
		__set_pmd_pte(kpte, address, new_pte);
		cpa->flushtlb = 1;
		do_split = 0;
	}

out_unlock:
	local_irq_restore(flags); // spin_unlock_irqrestore(&pgd_lock, flags);

	return do_split;
}

static int __change_page_attr(struct cpa_data *cpa, int primary)
{
	unsigned long address = cpa->vaddr;
	int do_split, err;
	unsigned int level;
	pte_t *kpte, old_pte;

repeat:
	kpte = lookup_address_fn(address, &level);
	if (!kpte)
		return 0;

	old_pte = *kpte;
	if (!pte_val(old_pte)) {
		if (!primary)
			return 0;
		printk(KERN_WARNING "CPA: called for zero pte. "
		       "vaddr = %lx cpa->vaddr = %lx\n", address,
		       cpa->vaddr);
		WARN_ON(1);
		return -EINVAL;
	}

	if (level == PG_LEVEL_4K) {
		pte_t new_pte;
		pgprot_t new_prot = pte_pgprot(old_pte);
		unsigned long pfn = pte_pfn(old_pte);

		pgprot_val(new_prot) &= ~pgprot_val(cpa->mask_clr);
		pgprot_val(new_prot) |= pgprot_val(cpa->mask_set);

		//new_prot = static_protections(new_prot, address, pfn);

		/*
		 * We need to keep the pfn from the existing PTE,
		 * after all we're only going to change it's attributes
		 * not the memory it points to
		 */
		new_pte = pfn_pte(pfn, canon_pgprot(new_prot));
		cpa->pfn = pfn;
		/*
		 * Do we really change anything ?
		 */
		if (pte_val(old_pte) != pte_val(new_pte)) {
			set_pte_atomic(kpte, new_pte);
			cpa->flushtlb = 1;
		}
		cpa->numpages = 1;
		return 0;
	}

	/*
	 * Check, whether we can keep the large page intact
	 * and just change the pte:
	 */
	do_split = try_preserve_large_page(kpte, address, cpa);
	/*
	 * When the range fits into the existing large page,
	 * return. cp->numpages and cpa->tlbflush have been updated in
	 * try_large_page:
	 */
	if (do_split <= 0)
		return do_split;

	/*
	 * We have to split the large page:
	 */
	err = split_large_page(kpte, address);
	if (!err) {
		cpa->flushtlb = 1;
		goto repeat;
	}

	return err;
}

static int __change_page_attr_set_clr(struct cpa_data *cpa, int checkalias)
{
	int ret, numpages = cpa->numpages;

	while (numpages) {
		/*
		 * Store the remaining nr of pages for the large page
		 * preservation check.
		 */
		cpa->numpages = numpages;

		ret = __change_page_attr(cpa, checkalias);
		if (ret)
			return ret;

		//if (checkalias) {
		//	ret = cpa_process_alias(cpa);
		//	if (ret)
		//		return ret;
		//}

		/*
		 * Adjust the number of pages with the result of the
		 * CPA operation. Either a large page has been
		 * preserved or a single page update happened.
		 */
		BUG_ON(cpa->numpages > numpages);
		numpages -= cpa->numpages;
		cpa->vaddr += cpa->numpages * PAGE_SIZE;
	}
	return 0;
}

static int change_page_attr_set_clr(unsigned long addr, int numpages,
				    pgprot_t mask_set, pgprot_t mask_clr,
				    int force_split)
{
	struct cpa_data cpa;
	int ret, cache, checkalias;

	/*
	 * Check, if we are requested to change a not supported
	 * feature:
	 */
	mask_set = canon_pgprot(mask_set);
	mask_clr = canon_pgprot(mask_clr);
	if (!pgprot_val(mask_set) && !pgprot_val(mask_clr) && !force_split)
		return 0;

	/* Ensure we are PAGE_SIZE aligned */
	if (addr & ~PAGE_MASK) {
		addr &= PAGE_MASK;
		/*
		 * People should not be passing in unaligned addresses:
		 */
		WARN_ON_ONCE(1);
	}

	cpa.vaddr = addr;
	cpa.numpages = numpages;
	cpa.mask_set = mask_set;
	cpa.mask_clr = mask_clr;
	cpa.flushtlb = 0;
	cpa.force_split = force_split;

	/* No alias checking for _NX bit modifications */
	checkalias = (pgprot_val(mask_set) | pgprot_val(mask_clr)) != _PAGE_NX;

	ret = __change_page_attr_set_clr(&cpa, checkalias);

	/*
	 * Check whether we really changed something:
	 */
	if (!cpa.flushtlb)
		goto out;

	/*
	 * No need to flush, when we did not set any of the caching
	 * attributes:
	 */
	cache = cache_attr(mask_set);

	/*
	 * On success we use clflush, when the CPU supports it to
	 * avoid the wbindv. If the CPU does not support it and in the
	 * error case we fall back to cpa_flush_all (which uses
	 * wbindv):
	 */
	//if (!ret && cpu_has_clflush)
	//	cpa_flush_range(addr, numpages, cache);
	//else
	//	cpa_flush_all(cache);

out:
	//cpa_fill_pool(NULL);

	return ret;
}

static inline int change_page_attr_set(unsigned long addr, int numpages,
				       pgprot_t mask)
{
	return change_page_attr_set_clr(addr, numpages, mask, __pgprot(0), 0);
}

#endif
