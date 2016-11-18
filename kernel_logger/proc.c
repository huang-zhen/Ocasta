/*
 * Ocasta kernel_logger
 * Copyright (C) 2016 Zhen Huang 
*/

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <syscall.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <assert.h>
#include "proc.h"

struct proc {
        int pid;
        char status;
};

struct proctab {
        int n;    /* number of entries filled */
        int nmax; /* number of entries allocated */
        struct proc *tab; /* array of proc structures */
};

static int
get_link(int pid, char *name, char *buf)
{
        char file[80];
        int ret;

        sprintf(file, "/proc/%d/%s", pid, name);
        if ((ret = readlink(file, buf, MAX_PATH - 1)) < 0) {
                fprintf(stderr, "readlink: %s: %s\n", file, strerror(errno));
                ret = 0;
                return 0;
        }
        buf[ret] = 0;
        return ret + 1;
}

static int
get_file(int pid, char *name, char *buf)
{
        char file[80];
        int fd, num_read;

        sprintf(file, "/proc/%d/%s", pid, name);
        if ((fd = open(file, O_RDONLY, 0)) < 0) {
                fprintf(stderr, "open: %s: %s\n", file, strerror(errno));
                return 0;
        }
        if ((num_read = read(fd, buf, MAX_PATH)) < 0) {
                fprintf(stderr, "read: %s: %s\n", file, strerror(errno));
                return 0;
        }
        if (num_read > 0) {
                buf[num_read - 1] = 0;
        }
        close(fd);
        return num_read;
}

static int
look_up_our_self()
{
        int fd, pid, num_read;
        char buf[5];

        if ((fd = open("/proc/self/stat", O_RDONLY, 0)) < 0) {
                fprintf(stderr, "open: /proc/self/stat: %s\n", strerror(errno));
                return -1;
        }
        if ((num_read = read(fd, buf, 4)) < 4) {
                fprintf(stderr, "read: /proc/self/stat: %s\n", strerror(errno));
                return -1;
        }
        buf[4] = 0;
        sscanf(buf, "%d", &pid);
        close(fd);
        return pid;
}

static int
is_kernel_thread(int pid)
{
        int num_read;
        char buf[MAX_PATH];

        /* ignores errors in get_file */
        num_read = get_file(pid, "cmdline", buf);
        if (num_read == 0)
                return 1;
        return 0;
}

/* return the running, stopped, etc. status of a process */
/* return 0 if the process can't be stopped */
/* return -1 on error */
static char
proc_status(int pid)
{
        char buf[MAX_PATH];
        char *s;
        char status;
        int kthread;

        kthread = is_kernel_thread(pid);
        if (kthread < 0)
                return kthread; /* error */
        if (kthread > 0)
                return 0; /* these threads can't be stopped */
        if (get_file(pid, "stat", buf) <= 0)
                return -1;
        s = strrchr(buf, ')') + 2;
        sscanf(s, "%c", &status);
        return status;
}

/* returns next pid or 0 */
static int
nextpid(DIR *procdir) {
        struct dirent *ent;

        for (;;) {
                ent = readdir(procdir);
                if (!ent || !ent->d_name)
                        return 0;
                if(*ent->d_name > '0' && *ent->d_name <= '9')
                        break;
        }
        return strtoul(ent->d_name, NULL, 10);
}


typedef int (*compfn)(const void*, const void*);

int
pid_cmp_fn(struct proc *a, struct proc *b)
{
        if (a->pid < b->pid)
                return -1;
        else if (a->pid > b->pid)
                return 1;
        return 0;
}

static struct proctab *
proctab_new(int n)
{
        struct proctab *p = calloc(1, sizeof(struct proctab));

        if (n > 0) {
                p->tab = calloc(n, sizeof(struct proc));
        }
        return p;
}

static void
proctab_free(struct proctab *p)
{
        if (!p)
                return;
        if (p->tab)
                free(p->tab);
        free(p);
}

static void
proctab_add(struct proctab *p, int pid, char status)
{
        if (p->n >= p->nmax) {
                int nmax = (p->nmax + 1) << 1;

                p->tab = realloc(p->tab, nmax * sizeof(struct proc));
                p->nmax = nmax;
        }
        p->tab[p->n].pid = pid;
        p->tab[p->n].status = status;
        p->n++;
}

static struct proctab *
readproctab(void)
{
        struct proctab *p = proctab_new(0);
        int pid;
        DIR *procdir;
        
        if (!(procdir = opendir("/proc"))) {
                perror("opendir: /proc");
                proctab_free(p);
                return NULL;
        }
        do {
                pid = nextpid(procdir);
                if (pid) {
                        proctab_add(p, pid, proc_status(pid));
                }
        } while (pid);
        if (procdir)
                closedir(procdir);
        qsort(p->tab, p->n, sizeof(struct proc), (compfn)pid_cmp_fn);
        return p;
}

/* returns TRUE if any processes were stopped */
static int
stop_processes(struct proctab *sp, int self_pid)
{
        int n;
        int stopped = 0;
        struct proctab *p = readproctab();

        if (!p)
                return 1; /* try again */
        for (n = 0; n < p->n; n++) {
                if (p->tab[n].pid == 1 || p->tab[n].pid == self_pid ||
                    p->tab[n].status == 'T' || p->tab[n].status <= 0)
                        continue;
                debug_log("start: stop_processes: nr = %d, pid = %d\n",
                          n, p->tab[n].pid);
                if (kill(p->tab[n].pid, SIGSTOP) < 0) {
	                fprintf(stderr, "kill: sigstop: pid = %d: %s\n",
                                p->tab[n].pid, strerror(errno));
                } else {
                        /* store all the processes we stopped.
                           status is not used. */
                        proctab_add(sp, p->tab[n].pid, 'T');
                }
                debug_log("stop: stop_processes: nr = %d, pid = %d\n",
                          n, p->tab[n].pid);
                stopped = 1;
        }
        proctab_free(p);
        return stopped;
}

/* custom method for getting the start time of a process */
static int
custom_pid_time(int procfd, pid_t pid)
{
        int err;
        unsigned long data = pid;
        if ((err = ioctl(procfd, AUDIT_SNAPSHOT_PROC_CMD, &data)) < 0) {
                fprintf(stderr, "ioctl: /proc/snapshot: pid: %d: %s\n", pid,
                        strerror(errno));
                return 0;
        }
        return (int)data;
}

static int
get_pid_time(int procfd, pid_t pid)
{
        /* cache the start time for pid 1. could cache others */
        static int init_pid_time = -1;
        if (init_pid_time < 0) {
                init_pid_time = custom_pid_time(procfd, 1);
        }
        if (pid == 1)
                return init_pid_time;
        return custom_pid_time(procfd, pid);
}

static void
get_name_user_group_id(int pid, char *comm, unsigned int *uid,
                       unsigned int *euid, unsigned int *suid, 
                       unsigned int *gid, unsigned int *egid,
                       unsigned int *sgid)
{
        char buf[MAX_PATH];
        char *str;
        int ret;
        int dummy;

        if (get_file(pid, "status", buf) <= 0)
                return;
        /* get name */
        ret = sscanf(buf, "Name:\t%s\n", comm);
        if (ret < 1) {
                fprintf(stderr, "get_user_group_id: %d: name not found\n", pid);
        }
        comm[16-1] = 0;
        /* get uid, gid, etc. */
        str = strstr(buf, "Uid:");
        if (!str) {
                fprintf(stderr, "get_user_group_id: %d: uid not found\n", pid);
                return;
        }
        ret = sscanf(str, "Uid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\n",
                     uid, euid, suid, &dummy, gid, egid, sgid, &dummy);
        if (ret < 8) {
                fprintf(stderr, "get_user_group_id: %d: %d uids found\n", pid,
                        ret);
        }
}

static int
send_fork(int pid, int procfd, int fd)
{
        int event_size = sizeof(fork_class);
        char pwd_buf[MAX_PATH]; int pwd_len = get_link(pid, "cwd", pwd_buf);
        int len = event_size + pwd_len;
        void *data = alloca(len);
        fork_class *event = data;
        int ret;
        unsigned int dummy;

        memset(data, 0, len);
        event->pwd_len = pwd_len;
        /* get uid, etc., ignore errors */
        get_name_user_group_id(pid, event->comm, &event->user_id,
                               &event->euser_id, &dummy, &event->group_id,
                               &event->egroup_id, &dummy);
        event->clone_flags = SIGCHLD;
        memcpy(data + event_size, pwd_buf, pwd_len);
        len = audit_generic(AUDIT_CLASS_FORK, SYS_fork, 1,
                            (header_token *)event, event_size, 1,
                            event->pwd_len, procfd);
        event->t_header.ret = pid; /* pid of child process */
        event->child_pid_time = get_pid_time(procfd, pid);
        if ((ret = write(fd, data, len)) < 0) {
                fprintf(stderr, "send_fork: write: %s\n", strerror(errno));
        }
        return ret;
}

static int
send_execve(int pid, int procfd, int fd)
{
        int event_size = sizeof(exec_class);
        char filename[MAX_PATH]; int filename_len = get_link(pid, "exe",
                                                             filename);
        char args[MAX_PATH]; int arg_len = get_file(pid, "cmdline", args);
        char envs[MAX_PATH]; int env_len = get_file(pid, "environ", envs);
        int len = event_size + filename_len + arg_len + env_len;
        void *data = alloca(len);
        void *cur;
        exec_class *event = data;
        char dummy[16];
        struct custat stat;
        char parentname[MAX_PATH];
        int ret;

        memset(data, 0, len);
        /* get inode and parent inode numbers of executable, ignore errors */
        if (custom_stat(procfd, filename, &stat) >= 0) {
                SET_INODE_NR(&event->i_nr, stat.i_dev, stat.i_ino, stat.i_igen,
                             stat.i_mode);
        }
        strncpy(parentname, filename, MAX_PATH);
        dirname(parentname);
        if (custom_stat(procfd, parentname, &stat) >= 0) {
                SET_INODE_NR(&event->parent_i_nr, stat.i_dev, stat.i_ino, 
                             stat.i_igen, stat.i_mode);
        }
        /* get uid, etc., ignore errors */
        get_name_user_group_id(pid, dummy, &event->ruid,
                               &event->euid, &event->suid, &event->rgid,
                               &event->egid, &event->sgid);
        cur = data + event_size;
        memcpy(cur, filename, filename_len);
        event->filename_len = filename_len;
        cur += filename_len;
        memcpy(cur, args, arg_len);
        event->arg_len = arg_len;
        cur += arg_len;
        memcpy(cur, envs, env_len);
        event->env_len = env_len;
        len = audit_generic(AUDIT_CLASS_EXEC, SYS_execve, pid,
                            (header_token *)event, event_size, 3,
                            len - event_size, procfd);
        if ((ret = write(fd, data, len)) < 0) {
                fprintf(stderr, "send_execve: write: %s\n", strerror(errno));
        }
        return ret;
}

static int stat_debug = 0;

/* we write a custom stat to get the inode generation number 
*/
static int
__custom_stat(int procfd, const char *name, struct custat *s, int untaint)
{
        int err = 0;
        int flag = AUDIT_SNAPSHOT_STAT_CMD;
        char buf[PATH_MAX];
        
        strcpy(buf, name);
        if (untaint) { /* this flag is used during the original snapshot */
                flag = AUDIT_SNAPSHOT_STAT_UNTAINT_CMD;
        }
        if ((err = ioctl(procfd, flag, buf)) < 0) {
                fprintf(stderr, "ioctl: /proc/snapshot: file: %s: %s\n", name, 
                        strerror(errno));
                return err;
        }
        memcpy(s, buf, sizeof(struct custat));
        
        if (stat_debug) {
                struct stat sbuf;
                if ((err = lstat(name, &sbuf)) < 0) {
                        fprintf(stderr, "lstat: %s: %s\n", name,
                               strerror(errno));
                }
                assert(s->i_dev == sbuf.st_dev);
                assert(s->i_ino == sbuf.st_ino);
                assert(s->i_mode == sbuf.st_mode);
                assert(s->i_nlink == sbuf.st_nlink);
                assert(s->i_uid == sbuf.st_uid);
                assert(s->i_gid == sbuf.st_gid);
        }
        return err;
}

int
custom_stat(int procfd, const char *name, struct custat *s)
{
        return __custom_stat(procfd, name, s, 0);
}

int
custom_stat_untaint(int procfd, const char *name, struct custat *s)
{
        return __custom_stat(procfd, name, s, 1);
}

/* try stopping all user level processes */
/* this function doesn't stop kernel threads and it is race-prone */
void *
stop_all_processes()
{
        int n = 0;
        int self_pid = look_up_our_self();
        int max_tries = 5; /* try no more times */
        struct proctab *sp = proctab_new(0); /* store all stopped processes */
        
        while (self_pid > 0 && n < max_tries && stop_processes(sp, self_pid)) {
                n++;
                debug_log("calling stop_processes: %d\n", n);
        }
        return sp;
}

/* resume all processes that we stopped */
void
resume_all_processes(void *sp)
{
        int n;
        struct proctab *p = sp;

        for (n = 0; n < p->n; n++) {
                if (kill(p->tab[n].pid, SIGCONT) < 0) {
                        fprintf(stderr, "kill: sigcont: pid = %d: %s\n",
                                p->tab[n].pid, strerror(errno));
                }
        }
        proctab_free(sp);
}

/* auditing routines */
/* similar code in ocasta_module.c */
int
audit_generic(enum audit_class_type class, unsigned short id, int pid, 
              header_token *event, int event_size, int nr_blocks, int datalen,
              int procfd)
{        
        event->event_class = class;
        event->event_id = id;
        event->event_size = event_size - sizeof(header_token);
        event->ret = 0;
        event->pid = pid;
//        event->pid_time = get_pid_time(procfd, pid);
        if (gettimeofday(&event->time, NULL) < 0) {
                /* ignore error */
                fprintf(stderr, "gettimeofday: %s\n", strerror(errno));
        }
        event->num_blocks = nr_blocks;
        event->data_size = datalen;
        return event_size + datalen;
}

int
send_process_info(int procfd, int outfd, int debug)
{
        int err = 0;
        int n;
        struct proctab *p = NULL;
  
        p = readproctab();

        for (n = 0; n < p->n; n++) {
                if (debug) {
                        /* no error and not a kernel thread */
                        if (p->tab[n].status > 0) {
                                send_fork(p->tab[n].pid, procfd, outfd);
                                send_execve(p->tab[n].pid, procfd, outfd);
                        }
                } else {
                        /* stopped or init thread */
                        if ((p->tab[n].status == 'T') || (p->tab[n].pid == 1)) {
                                send_fork(p->tab[n].pid, procfd, outfd);
                                send_execve(p->tab[n].pid, procfd, outfd);
                        }
                }
        }
        proctab_free(p);
        return err;
}
