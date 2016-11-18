/*
 * Ocasta kernel_logger
 * Copyright (C) 2016 Zhen Huang 
*/

#include <stdio.h>
#include <string.h>
#include <gconf/gconf-value.h>
#include "gconf_msg.h"
#include "store_gconf_log.h"
#include "file_seq.h"

#define OCASTA_DIR "/etc/ocasta"
#define MAX_FILESIZE 2 * 1024 * 1024 * 1024  // 2GB

static int log_fd = -1;
static char log_dir[512];

void set_gconf_log_dir(const char *dir)
{
	strncpy(log_dir, dir, sizeof(log_dir));
}

char *cmd2str(int cmd)
{
	static char *msg_cmd_name[] = {
		"UNKNOWN",
		"GETVALUE",
		"SETVALUE",
		"GETVALUELIST",
		"SETVALUELIST",
	};
	if (cmd < GCONF_CMD_DONE)
		return msg_cmd_name[cmd];
	else
		return NULL;
}

int store_gconf_log(msg_t *msg)
{
	int seq_no;
	char filename[80];
	char buf[sizeof(msg_t)];
	off_t file_len;
	int ret = 0;
	struct tm *t;

	if (log_fd == -1) {
		if (log_dir[0] == '\0') {
			log_fd = dup(1);
		} else {
			log_fd = open_file_seq(log_dir, "gconf", 1000, &seq_no, filename);
			if (log_fd != -1)
				log_seqno(OCASTA_DIR, "ocasta_gconf", filename);
			else
				return -1;
		}
	}
	t = localtime(&msg->timestamp);	
	int n = sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d %d %d \"%s\" %s \"%s\" %d ", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, msg->pid, msg->tid, msg->procname, cmd2str(msg->cmd), msg->key, msg->vtype);
	if (msg->cmd == GCONF_CMD_SET_VALUE || msg->cmd == GCONF_CMD_SET_VALUE_LIST) {
		switch(msg->vtype) {
		case GCONF_VALUE_INT:
		case GCONF_VALUE_BOOL:
			sprintf(buf + n, "%d\n", *(int *)msg->value);
			break;
		case GCONF_VALUE_FLOAT:
			sprintf(buf + n, "%lf\n", *(double *)msg->value);
			break;
		case GCONF_VALUE_STRING:
			sprintf(buf + n, "\"%s\"\n", msg->value);
			break;
		default:
			sprintf(buf + n, "UNKNOWN\n");
			break;
		}
	} else
		sprintf(buf + n, "\n");
	if (write(log_fd, buf, strlen(buf)) == -1)
		ret = -2;
	file_len = lseek(log_fd, 0, SEEK_CUR);
	if (file_len >= (off_t)MAX_FILESIZE) {
		close(log_fd);
		log_fd = -1;
	}
	return ret;
}

