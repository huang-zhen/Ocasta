/*
 * gconf_msg.h
 */

#ifndef GCONF_MSG_H
#define GCONF_MSG_H

#include <sys/types.h>
#include <sys/ipc.h>
#include <unistd.h>

#define PROCNAME_LEN 256
#define KEY_LEN 1024
#define VALUE_LEN 4096

enum msg_cmd_type {
	GCONF_CMD_UNKNOWN,
	GCONF_CMD_GET_VALUE,
	GCONF_CMD_SET_VALUE,
	GCONF_CMD_GET_VALUE_LIST,
	GCONF_CMD_SET_VALUE_LIST,
	GCONF_CMD_DONE
};

typedef struct
{
	long mtype;
	uid_t uid;
	pid_t pid;
	pid_t tid;
	time_t timestamp;
	char procname[PROCNAME_LEN];
	int cmd;
	char key[KEY_LEN];
	int vtype;
	char value[VALUE_LEN];
} msg_t;
	
int send_gconf_msg(int cmd, msg_t *qbuf);
int recv_gconf_msg(msg_t *qbuf, int *valid);

#endif

