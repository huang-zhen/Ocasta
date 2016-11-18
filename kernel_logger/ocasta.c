/**
 * The ocasta start program
 */

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/dir.h>
#include <dirent.h>
#include <stdarg.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <netdb.h>
#include <popt.h>
#include <libgen.h>
#include <time.h>
#include <linux/netlink.h>
#include <syslog.h>
#include <sys/wait.h>
#include "ocasta_module.h"
#include "snapshot.h"
#include "file_seq.h"
#include "daemonize.h"
#include "gconf_msg.h"
#include "store_gconf_log.h"

#define __STR(n) #n
#define STR(n) __STR(n)

#ifndef VERSIONING
static int open_file(const char *dirname, int *seq_no);
static int open_socket(const char *host, int port);
#endif /* VERSIONING */
#ifdef SAVE_FILE_DATA
static int open_data_file(const char *dirname, int seq_no, char *file_name);
#endif /* SAVE_FILE_DATA */
static char *prog;

#define MAX_PAYLOAD 4096
#define MAX_FILESIZE 2 * 1024 * 1024 * 1024  // 2GB
//#define MAX_FILESIZE 16 * 1024 * 1024  // 16MB

int init_netlink()
{
	struct sockaddr_nl src_addr;
	int sock_fd;
	
	sock_fd = socket(AF_NETLINK, SOCK_RAW, 17);
	if (sock_fd < 0) {
		perror("creating socket\n");
		return -1;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 0;
	if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) != 0) {
		perror("bind socket failed\n");
		close(sock_fd);
		return -1;
	}
	return sock_fd;
}

void
recv_frame(int sock_fd, int file_fd, char *dirname, int seq_no)
{
	struct sockaddr_nl dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct msghdr msg;
	struct iovec iov;
	int len, ret;
	off_t file_len;
	
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	iov.iov_base = (void *)nlh;
	iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	sprintf(NLMSG_DATA(nlh), "%d ENQ", getpid());

	syslog(LOG_INFO, "Sending message to kernel\n");
	len = sendmsg(sock_fd, &msg, 0);
	if (len < 0)
		syslog(LOG_NOTICE, "Sending message to kernel failed\n");

	syslog(LOG_INFO, "Waiting for message from kernel\n");
	while (1) {
		len = recvmsg(sock_fd, &msg, 0);
		if (len > 0) {
			//syslog(LOG_INFO, "Received message payload(%d): (%d)%s\n", len, nlh->nlmsg_len, (char *)NLMSG_DATA(nlh));
			if (nlh->nlmsg_type == NLMSG_DONE)
				break;
			ret = write(file_fd, NLMSG_DATA(nlh), nlh->nlmsg_len - sizeof(*nlh));
			file_len = lseek(file_fd, 0, SEEK_CUR);
			if (file_len >= (off_t)MAX_FILESIZE) {
				close(file_fd);
				file_fd = open_file(dirname, &seq_no);
				if (file_fd < 0) {
					syslog(LOG_NOTICE, "Openning data file failed\n");
					break;
				}
			}
			if (ret <= 0) {
				syslog(LOG_NOTICE, "Writing captured data failed %d\n", ret);
				break;
			}
		} else {
			syslog(LOG_NOTICE, "recvmsg failed\n");
			break;
		}
	}
	close(sock_fd);
}

/*
 * recv_msg: process gconf messages
 */
void
recv_msg()
{
	msg_t msg;
	int ret;
	int valid;

	while (1) {
		ret = recv_gconf_msg(&msg, &valid);
		if (ret != -1) {
			if (valid) {
				syslog(LOG_INFO, "%s get cmd:%d\n", __FUNCTION__, msg.cmd);
				store_gconf_log(&msg);
				if (msg.cmd == GCONF_CMD_DONE)
					break;
			} else
				syslog(LOG_NOTICE, "%s get invalid message type:%ld\n", __FUNCTION__, msg.mtype);
		} else {
			syslog(LOG_NOTICE, "%s error:%d\n", __FUNCTION__, errno);
			break;
		}
	}
}

int
main(int argc, const char *argv[])
{
        char device_name[] = AUDIT_DEV_FILE;
        int in_fd = -1;
        int out_fd = -1;
        char *hostname = NULL;
        char *dirname = NULL;
#ifdef SAVE_FILE_DATA
	int data_fd = -1;
	char filename[80];
#endif
        int no_snapshot = 1; /* don't take a snapshot */
        int rw_type = AUDIT_RW_INF;
        int max_ready = MAX_READY_PAGES;
        int max_free = MAX_FREE_PAGES;
	int load_autoconf = 0; 
	int switch_audit = 0;
	int stop_audit = 0;
	int show_version_log = 0;
	int c; 
	int err;
	poptContext context;    /* context for parsing command-line options */
        struct poptOption options_table[] = {
                {"server", 's', POPT_ARG_STRING, &hostname, 0,
                 "send data to server", "server"},
                {"directory", 'd', POPT_ARG_STRING, &dirname, 0,
                 "send data to file", "directory"},
                {"no-snapshot", 't', POPT_ARG_NONE, &no_snapshot, 0,
                 "don't take a file-system snapshot at startup"},
                {"max-ready", 0, POPT_ARG_INT, &max_ready, 0,
                 "max nr of ready pages (default: " STR(MAX_READY_PAGES) ")"},
                {"max-free", 0, POPT_ARG_INT, &max_free, 0,
                 "max nr of free pages (default: " STR(MAX_FREE_PAGES) ")"},
                {"load autoconf", 'l', POPT_ARG_NONE, &load_autoconf, 0,
                 "load autoconf file", "load autoconf"},
                {"show version log", 'v', POPT_ARG_INT, &show_version_log, 0,
                 "show version log", "show version log"},
                {"switch", 'w', POPT_ARG_NONE, &switch_audit, 0,
                 "switch auditing", "switch audit"},
                {"stop", 0, POPT_ARG_NONE, &stop_audit, 0,
                 "stop auditing", "stop audit"},
                {NULL, 'r', POPT_ARG_INT, &rw_type, 0,
                 "audit all data: " STR(AUDIT_RW_INF)
                 ", no data: " STR(AUDIT_RW_NONE)
                 ", audit " STR(AUDIT_RW_LENGTH) " bytes: " STR(AUDIT_RW_SET)
                 " (default: " STR(AUDIT_RW_INF) ")"},
                POPT_AUTOHELP {NULL, 0, 0, NULL, 0}
        };
	int netlink_sock;
	int seq_no = 1;

        prog = basename((char *)argv[0]);
        context = poptGetContext(NULL, argc, argv, options_table, 0);
        while ((c = poptGetNextOpt(context)) >= 0);
        if (c < -1) {   /* an error occurred during option processing */
                poptPrintUsage(context, stderr, 0);
                exit(1);
        }
        if (poptGetArg(context)) {
                poptPrintUsage(context, stderr, 0);
                exit(1);
        }
	openlog("ocasta", LOG_PID, LOG_LOCAL5);
        /* open audit device */
        if ((in_fd = open(device_name, O_RDONLY, 0)) < 0) {
                fprintf(stderr, "open %s: %s\n", device_name, strerror(errno));
                fprintf(stderr, "%s: try installing the audit module using "
                        "insmod ocasta_module\n", prog);
                goto out;
        }
	if (load_autoconf) {
		printf("load autoconf\n");
		if (ioctl(in_fd, AUDIT_LOAD_AUTOCONF, 1) < 0) {
                	perror("main: ioctl: AUDIT_LOAD_AUTOCONF");
		}
		goto out;
	}
	if (switch_audit) {
		printf("switch auditing...");
		err = ioctl(in_fd, AUDIT_SWITCH, 1);
		if (err < 0) {
			perror("main: ioctl: AUDIT_SWITCh");
		} else if (err == 0) {
			printf("off\n");
		} else if (err == 1) {
			printf("on\n");
		}
		goto out;
	}
	if (stop_audit) {
		printf("stop auditing\n");
		if (ioctl(in_fd, AUDIT_STOP, 1) < 0) {
                	perror("main: ioctl: AUDIT_STOP");
		}
		goto out;
	}
        if ((hostname && dirname) || (!hostname && !dirname)) {
                fprintf(stderr, "%s: specify either a server or "
                        "an output directory\n", prog);
                poptPrintUsage(context, stderr, 0);
                exit(1);
        }
        printf("%s: version %d.%d.%d\n", prog, AUDITMODULE_MAJOR_VERSION,
               AUDITMODULE_MINOR_VERSION, AUDITMODULE_PATCH_VERSION);
#ifndef VERSIONING
        out_fd = dirname ? open_file(dirname, &seq_no) : -1;
        if (out_fd < 0)
                exit(1);
#endif /* VERSIONING */
#ifdef SAVE_FILE_DATA
	data_fd = dirname ? open_data_file(dirname, 1, filename) : -1;
	if (data_fd < 0)
		exit(1);
        if (ioctl(in_fd, AUDIT_SET_DATA_FILE, data_fd) < 0) {
                fprintf(stderr, "%s: ioctl: AUDIT_SET_DATA_FILE: %s\n", prog,
                        strerror(errno));
                goto out;
        }
	if (ioctl(in_fd, AUDIT_SET_DATA_FILE_NAME, filename) < 0) {
	        fprintf(stderr, "%s: ioctl: AUDIT_SET_DATA_FILE_NAME: %s\n", prog,
	                strerror(errno));
	        goto out;
	}
#endif /* SAVE_FILE_DATA */
	if (ioctl(in_fd, AUDIT_SET_WORK_DIR, dirname) < 0) {
	        fprintf(stderr, "%s: ioctl: AUDIT_SET_WORK_DIR: %s\n", prog,
	                strerror(errno));
	        goto out;
	}
        if (ioctl(in_fd, AUDIT_SET_RW_DATA, rw_type) < 0) {
                fprintf(stderr, "%s: ioctl: AUDIT_SET_RW_DATA: %s\n", prog,
                        strerror(errno));
                goto out;
        }
        if (ioctl(in_fd, AUDIT_SET_MAX_READY_PAGES, max_ready) < 0) {
                fprintf(stderr, "%s: ioctl: AUDIT_SET_MAX_READY_PAGES: %s\n",
                        prog, strerror(errno));
                goto out;
        }
        if (ioctl(in_fd, AUDIT_SET_MAX_FREE_PAGES, max_free) < 0) {
                fprintf(stderr, "%s: ioctl: AUDIT_SET_MAX_FREE_PAGES: %s\n",
                        prog, strerror(errno));
                goto out;
        }
#ifdef VERSIONING
	if (ioctl(in_fd, AUDIT_SHOW_VERSION_LOG, show_version_log) < 0) {
               	perror("main: ioctl: AUDIT_SHOW_VERSION_LOG");
		goto out;
	}
#endif /* VERSIONING */
        if (no_snapshot == 0) {
                /* Take file-system snapshot for the following device types. */
                const char *device_types[] = {"ext3", "tmpfs", "devpts", NULL};

                /* From now on, all output and error messages will now go to
                 * /var/log/ocasta. This code detaches this process from
                 * tty by doing a fork and creating a new session */
                if (snapshot("/", device_types, out_fd) < 0) {
                        goto out;
                }
        }
        if (ioctl(in_fd, AUDIT_SEND, out_fd) < 0) {
                perror("main: ioctl: AUDIT_SEND");
                goto out;
        }
        printf("ocasta: auditing started successfully\n");
	daemonize(NULL);
	syslog(LOG_INFO, "auditing started successfully\n");
	pid_t child = fork();
	if (child > 0) {
		// parent process
		syslog(LOG_INFO, "auditing parent - child:%d\n", child);
		// for testing
		send_gconf_msg(GCONF_CMD_GET_VALUE, NULL);
		send_gconf_msg(GCONF_CMD_SET_VALUE, NULL);

		netlink_sock = init_netlink();
		recv_frame(netlink_sock, out_fd, dirname, seq_no);
		// signal child process to exit
		if (send_gconf_msg(GCONF_CMD_DONE, NULL) != -1) {
			waitpid(child, NULL, 0);
			remove_gconf_queue();
		} else
			syslog(LOG_NOTICE, "send_gconf_msg error:%d\n", errno);
		closelog();
	} else if (child == 0) {
		// child process
		syslog(LOG_INFO, "auditing child\n");
		recv_msg();
	}
        exit(0);
  out:
	if (in_fd > 0)
		close(in_fd);
        exit(1);
}

#ifndef VERSIONING
static int
open_file(const char *dirname, int *seq_no)
{
	int out_fd;
	char filename[80];

	out_fd = open_file_seq(dirname, "log", 1000, seq_no, filename);
	syslog(LOG_NOTICE, "%s %s returned %d\n", __FUNCTION__, filename, out_fd);
	if (out_fd > 0)
		log_seqno(dirname, "ocasta_log", filename);
        return out_fd;
}

/* Open the network - destination host and port */
static int
open_socket(const char *host, int port)
{
        struct hostent h;
        struct hostent *hp = &h;
        int socket_fd = -1;
        struct sockaddr_in sockaddr;
        int val;

        socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket_fd < 0) {
                perror("open_socket: socket");
                goto out;
        }
        hp = gethostbyname(host);
        if (hp == 0) {
                fprintf(stderr, "open_socket: gethostbyname %s: %s\n",
                        host, hstrerror(h_errno));
                goto out;
        }
        bcopy(hp->h_addr, &sockaddr.sin_addr, hp->h_length);
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_port = htons(port);

        if (connect(socket_fd, (struct sockaddr *)&sockaddr,
                    sizeof(sockaddr)) < 0) {
                fprintf(stderr, "open_socket: connect: %s: %d: %s\n",
                        host, port, strerror(errno));
                goto out;
        }
        val = 1;
        if (setsockopt(socket_fd, SOL_TCP, TCP_CORK, &val, sizeof(val)) < 0) {
                perror("open_socket: setsockopt: TCP_CORK");
        }
        return socket_fd;
  out:
        if (socket_fd >= 0)
                close(socket_fd);
        return -1;
}

#endif /* VERSIONING */

#ifdef SAVE_FILE_DATA
static int
open_data_file(const char *dirname, int seq_no, char *filename)
{
	int out_fd;

	out_fd = open_file_seq(dirname, "dat", 1000, &seq_no, filename);
	syslog(LOG_NOTICE, "%s %s returned %d\n", __FUNCTION__, filename, out_fd);
	log_seqno(dirname, "ocasta_dat", filename);
        return out_fd;
}
#endif /* SAVE_FILE_DATA */

