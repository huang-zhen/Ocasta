#include <asm/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <malloc.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <alloca.h>
#include "proc.h"
#include "snapshot.h"
#include "hmap.h"
#include <sys/ioctl.h>

#define HMAP_ELM_MAX 4096

struct link {
        struct {
                __u32 st_dev;
                __u32 st_ino;
        } ino;
        char filename[NAME_MAX];
        struct custat pstat;
        unsigned int nlink;
        HMAP_ENTRY(link) entry;
};

/* create a link hash table structure called link_hmap */
/* create a linked list data structure called link_list */
/* the hash table takes entries of type struct link */
HMAP_HEAD(link_hmap, link_list, link);

struct ino {
        dev_t st_dev;
        ino_t st_ino;
};

struct traversedir_data {
        int procfd;
        int fd;
        int *devices; /* list of devices that we wish to snapshot */
        struct link_hmap *map; /* hash table for hard links */
};

static int daemonize(void);
static int traversedir(const char *topdir, const char *devtype[], int procfd,
                       int outfd);
static int traversedir_real(const char *dirname, const struct custat *stat,
                            struct traversedir_data *d);
static int process_file(const char *filename, const struct custat *stat,
                        const struct custat *pstat, struct traversedir_data *d);
static int send_file(struct traversedir_data *d, unsigned short syscall,
                     const char *pathname, const struct custat *stat,
                     const struct custat *pstat, const char *srcpathname,
                     const struct custat *srcpstat);
static int *get_device_list(const char *devtype[]);
static int in_device_list(int *list, int dev_nr);

/**
 * Take file-system snapshot and send it to backend
 * 1. First stop processes
 * 2. Then take snapshot using module code
 *    - take module code (snapshot.c) and put it in ocasta_module
 *    - take the recursion code from stat.c and put it here
 *    - send inode data to the backend via out_fd
 * 3. Continue processes 
*/

static int proc_debug = 0;
static int untaint = 1;

/* make sure that stdout and stderr is redirected to a file and is not the 
 * terminal or else the process will deadlock if there are any error
 * messages.
 *
 * Also, make sure that this function is not called from a binary that is
 * on an NFS file system.
 */
int
snapshot(const char *topdir, const char *devtype[], int outfd)
{
        int err;
        void *sp = NULL;

        int procfd = 0;
        if (!proc_debug) {
                if (daemonize())
                        goto out;
        }
        debug_log("ocasta: starting: snapshot\n");
        if ((procfd = open(AUDIT_SNAPSHOT_FILE, O_RDWR)) < 0) {  
                fprintf(stderr, "open: %s: %s\n", AUDIT_SNAPSHOT_FILE, 
                        strerror(errno));
                return procfd;
        }
        if (!proc_debug) {
                debug_log("ocasta: starting: stop processes\n");
                sp = stop_all_processes();
                debug_log("ocasta: ending: stop processes\n");
        }
        debug_log("ocasta: starting process snapshot\n");
        err = send_process_info(procfd, outfd, proc_debug);
        debug_log("ocasta: ending: process snapshot\n");
        if (err < 0)
                goto out;
        debug_log("ocasta: starting: file snapshot\n");
        err = traversedir(topdir, devtype, procfd, outfd);
        debug_log("ocasta: ending file snapshot\n");
 out:
        if (!proc_debug) {
                debug_log("ocasta: starting: resume processes\n");
                resume_all_processes(sp);
                debug_log("ocasta: ending: resume processes\n");
        }
        close(procfd);
        debug_log("ocasta: ending: snapshot\n");
        return err;
}

static int
daemonize(void)
{
        /* Our process ID and Session ID */
        pid_t pid, sid;
        int log_fd;
        
        /* the next two lines ensure that any previous buffered data is
           sent out immediately. I think this may avoid deadlock when we
           stop all processes. */
        fsync(STDOUT_FILENO);
        fsync(STDERR_FILENO);
        /* Fork off the parent process */
        pid = fork();
        if (pid < 0) {
                perror("fork");
                return 1;
        }
        /* If we got a good PID, then we can exit the parent process. */
        if (pid > 0) {
                exit(0);
        }
        /* Change the file mode mask */
        umask(0);

        /* open log file */
        log_fd = open("/var/log/ocasta", O_CREAT|O_WRONLY|O_APPEND,
                      S_IREAD|S_IWRITE);
        if (log_fd < 0) {
                perror("open: /var/log/ocasta");
                return 1;
        }
        /* From now on all stdout and stderr will go to a log file.
         * This is needed because the snapshot code suspends all processes
         * which can lead to a deadlock if the output goes to a terminal. */
        if (dup2(log_fd, STDERR_FILENO) < 0) {
                perror("dup2");
                return 1;
        }
        if (dup2(log_fd, STDOUT_FILENO) < 0) {
                perror("dup2");
                return 1;
        }
        /* Create a new SID for the child process */
        sid = setsid();
        if (sid < 0) {
                perror("setsid");
                return 1;
        }
        /* Change the current working directory */
        if ((chdir("/")) < 0) {
                fprintf(stderr, "chdir: /: %s\n", strerror(errno));
                return 1;
        }
        /* Close the input file descriptor */
        close(STDIN_FILENO);
        return 0;
}

static int
traversedir(const char *topdir, const char *devtype[], int procfd, int outfd)
{
        int err = 0;
        struct custat stat, pstat;
        char parent_path[PATH_MAX];
        struct traversedir_data data;
        struct link_hmap map; /* a hash table for hard links */
        struct link_list array[HMAP_ELM_MAX];
        HMAP_INIT(&map, link_list, array, HMAP_ELM_MAX); /* init map */

        if (!(data.devices = get_device_list(devtype)))
                goto out;
        if(proc_debug && !untaint)
                err = custom_stat(procfd, topdir, &stat);
        else
                err = custom_stat_untaint(procfd, topdir, &stat);
        if (err < 0) goto out;
        if (!in_device_list(data.devices, stat.i_dev)) {
                fprintf(stderr, "traversedir: %s not in device list\n", topdir);
                err = -1;
                goto out;
        }
        if (strcmp(topdir, "/")) { /* not "/" dir */
                strcpy(parent_path, topdir);
                strcat(parent_path, "/..");
                if(proc_debug && !untaint)
                        err = custom_stat(procfd, parent_path, &pstat);
                else 
                        err = custom_stat_untaint(procfd, parent_path, &pstat);
                if (err < 0) goto out;
        } else { /* "/" dir */
                pstat = stat;
        }
        data.procfd = procfd;
        data.fd = outfd;
        data.map = &map;
        /* send data for topdir */
        err = process_file(topdir, &stat, &pstat, &data);
        if (err < 0) goto out;
        /* start the recursion */
        err = traversedir_real(topdir, &stat, &data);
  out:
        if (data.devices)
                free(data.devices);
        return err;
}

static int
traversedir_real(const char *dirname, const struct custat *stat,
                 struct traversedir_data *d)
{
        int err = 0;
        DIR *dir;
        struct dirent *entry;
        struct custat cstat; /* stat information for child */
        
        if (!(dir = opendir(dirname))) {
                fprintf(stderr, "opendir: %s: %s\n", dirname, strerror(errno));
                return -1;
        }
        /* change directory */
        err = fchdir(dirfd(dir));
        if (err < 0) goto out;

        for (entry = readdir(dir); entry; entry = readdir(dir)) {
                if (strcmp(entry->d_name, ".") == 0 ||
                    strcmp(entry->d_name, "..") == 0)
                        continue;
                if (proc_debug && !untaint)
                        err = custom_stat(d->procfd, entry->d_name, &cstat);
                else
                        err = custom_stat_untaint(d->procfd, entry->d_name, 
                                                  &cstat);
                if (err < 0) goto out;
                
                /* Send mkdir/creat/symlink/link to backend with stat data */
                err = process_file(entry->d_name, &cstat, stat, d);
                if (err < 0) goto out;

                if (!S_ISDIR(cstat.i_mode) ||
                    !in_device_list(d->devices, cstat.i_dev))
                        continue;
                err = traversedir_real(entry->d_name, &cstat, d);
                if (err < 0) goto out;
                /* change directory back */
                err = fchdir(dirfd(dir));
                if (err < 0) goto out;
        }
  out:
        closedir(dir);
        return err;
}

static int
process_file(const char *filename, const struct custat *stat,
             const struct custat *pstat, struct traversedir_data *d)
{
        int err = 0;

        if(proc_debug && stat->i_taint) {
                char current_dir[PATH_MAX];
                *current_dir = '\0';
                if(!getcwd(current_dir, PATH_MAX)) {
                        perror("getcwd");
                }
                printf("%s/%s\n", current_dir, filename);
        }
        
        if (S_ISDIR(stat->i_mode)) {
                err = send_file(d, SYS_mkdir, filename, stat, pstat, 0, 0);
                return err;
        }
        /* all other file types can have multiple links */
        if (stat->i_nlink > 1) { /* deal with hard links */
                struct link *plink, *clink;

                clink = (struct link *)malloc(sizeof(struct link));
                if (!clink) {
                        fprintf(stderr, "malloc: %s\n", strerror(errno));
                        return -1;
                }
                strcpy(clink->filename, filename);
                clink->ino.st_dev = stat->i_dev;
                clink->ino.st_ino = stat->i_ino;
                memcpy(&(clink->pstat), pstat, sizeof(struct custat));
                /* we should see n - 1 more links */
                clink->nlink = stat->i_nlink - 1;
                clink->entry.key = &clink->ino;
                /* put clink in hash table. */
                HMAP_PUT(d->map, link, clink, plink, entry, sizeof(clink->ino));
                /* plink gets updated by HMAP_PUT. It is non-null 
                * if there was a previous link in the hash table. */
                if (plink) { /* previous link was seen */
                        clink->nlink = plink->nlink - 1;
                        err = send_file(d, SYS_link, filename, stat, pstat,
                                        plink->filename, &(plink->pstat));
                        /* HMAP_PUT removes the previous link from hash table */
                        free(plink);
                        if (!clink->nlink) { /* last link */
                                HMAP_GET(d->map, link, clink, plink, entry,
                                         sizeof(clink->ino));
                                assert(plink);
                                /* HMAP_GET removes clink from hash table */
                                free(clink);
                        }
                        return err;
                }
                /* if plink is NULL, then the first link is handled either 
                 * by send_symlink or send_file */
        }
        if (S_ISLNK(stat->i_mode)) {
                char buf[PATH_MAX];

                err = readlink(filename, buf, PATH_MAX);
                if (err < 0) {
                        fprintf(stderr, "readlink: %s\n", strerror(errno));
                        return err;
                }
                buf[err] = 0; /* zero out the end of the buffer */
                err = send_file(d, SYS_symlink, filename, stat, pstat, buf, 0);
                return err;
        }
        /* for all file types, we can send a mknod (see 2 mknod) */
        err = send_file(d, SYS_mknod, filename, stat, pstat, 0, 0);
        return err;
}

static int
send_file(struct traversedir_data *d, unsigned short syscall,
          const char *pathname, const struct custat *stat,
          const struct custat *pstat, const char *srcpathname,
          const struct custat *srcpstat)
{
        int len = strlen(pathname) + 1;
        int srclen = srcpathname ? strlen(srcpathname) + 1 : 0;
        int event_size = sizeof(indmac_class);
        void *data = alloca(event_size + len + srclen);
        indmac_class *event = data;
        int err;

        event->filename_len = len;
        event->source_filename_len = srclen;
        SET_INODE_NR(&event->i_nr, stat->i_dev, stat->i_ino, stat->i_igen,
                     stat->i_mode);
//        SET_INODE_NR(&event->parent_i_nr, pstat->i_dev, pstat->i_ino,
 //                    pstat->i_igen, pstat->i_mode);
//        if (srcpstat) {
//                SET_INODE_NR(&event->source_parent_i_nr, srcpstat->i_dev, 
//                             srcpstat->i_ino, srcpstat->i_igen,
//                             srcpstat->i_mode);
//        } else {
//                SET_INODE_NR(&event->source_parent_i_nr, 0, 0, 0, 0);
//        }
        event->flags = 0;
        event->mode = stat->i_mode & ~S_IFMT;
//        event->owner = stat->i_uid;
//        event->group = stat->i_gid;
        event->isfirst = syscall != SYS_link ? 1 : 0;
        memcpy(data + event_size, pathname, len);
        memcpy(data + event_size + len, srcpathname, srclen);
        len = audit_generic(AUDIT_CLASS_INDMAC, syscall, 1,
                            (header_token *)event, event_size, 2, len + srclen, 
                            d->procfd);
        if ((err = write(d->fd, data, len)) < 0) {
                fprintf(stderr, "send_file: write: %s\n", strerror(errno));
        }
        return err;
}

static int *
get_device_list(const char *devtype[])
{
        int n = 0, nmax = 0;
        int *tab = NULL;
        FILE *f;
        char dev[PATH_MAX];
        char dir[PATH_MAX];
        char type[20];
        char param[200];
        int v1, v2;
        struct stat buf;
        
        f = fopen("/proc/mounts", "r");
        if (!f) return NULL;
        while (fscanf(f, "%s %s %s %s %d %d\n", dev, dir, type, param,
                      &v1, &v2) != EOF) {
                int i = 0;
                int found = 0;

                /* is the device type in our list? */
                while (devtype[i]) {
                        if (!strcmp(devtype[i], type)) { /* match */
                                found = 1;
                                break;
                        }
                        i++;
                }
                if (!found)
                        continue;
                if (stat(dir, &buf) < 0) {
                        fprintf(stderr, "stat: %s: %s\n", dir, strerror(errno));
                        continue;
                }
                /* remove duplicate device ids */
                found = 0;
                for (i = 0; i < n; i++) {
                        if (tab[i] == buf.st_dev) {
                                found = 1;
                                break;
                        }
                }
                if (found)
                        continue;
                if (n >= nmax) {
                        nmax = (nmax + 1) << 1;
                        tab = realloc(tab, (nmax + 1) * sizeof(int));
                }
                tab[n] = buf.st_dev;
                n++;       
        }
        if (tab)
                tab[n] = 0;
        return tab;
}

static int
in_device_list(int *list, int dev_nr)
{
        for (; *list; list++) {
                if (dev_nr == *list)
                        return 1;
        }
        return 0;
}

#if 0
/* for debugging */
/* Look at the comments above the snapshot() function */
int
main(int argc, char *argv[])
{
        int err, out_fd;
        const char *device_types[] = {"ext3", "tmpfs", "devpts", NULL};
        
        if (argc != 3) {
                fprintf(stderr, "Usage: snapshot dir [0|1] (for untainting) \n");
                return 1;
        }
        /* the snapshot data will go to this file */
        out_fd = open("/tmp/ocasta_snapshot.out", O_WRONLY|O_CREAT|O_APPEND,
                      S_IREAD|S_IWRITE);
        if (out_fd < 0) {
                perror("open: /tmp/ocasta_snapshot.out");
                return 1;
        }
        untaint = atoi(argv[2]);
        proc_debug = 1;
        err = snapshot(argv[1], device_types, out_fd);
        return err;
}
#endif
