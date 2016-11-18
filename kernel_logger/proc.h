#ifndef STOP_PROCESS_H
#define STOP_PROCESS_H
#include <time.h>
#include "ocasta_module.h"

#define SET_INODE_NR(inr, d, i, g, m) \
	(inr)->dev = d; \
	(inr)->inode = i; \
	(inr)->gen = g; \
	(inr)->type = m & S_IFMT

#define debug_log(str, args...) \
do { \
        char a[30]; \
        time_t now = time(NULL); \
        strftime(a, 30, "%h %e %T ", localtime(&now)); \
        fprintf(stderr, "%s", a); \
        fprintf(stderr, str, ## args); \
} while(0)

int custom_stat(int procfd, const char *name, struct custat *stat);
int custom_stat_untaint(int procfd, const char *name, struct custat *stat);
void *stop_all_processes();
void resume_all_processes(void *);
int audit_generic(enum audit_class_type class, unsigned short id, int pid,
                  header_token *event, int event_size, int nr_blocks,
                  int datalen, int procfd);
int send_process_info(int procfd, int outfd, int debug);

#endif /* STOP_PROCESS_H */
