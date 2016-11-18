/*
 * gconf_msg.c
 */
/*
 * Ocasta kernel_logger
 * Copyright (C) 2016 Zhen Huang 
*/

#include <sys/msg.h>
#include <sys/types.h>
#include <unistd.h>
#include <memory.h>
#include "gconf_msg.h"

#define FTOK_PATH "/etc/ocasta"
#define MSG_TYPE 0x11122011
#define MSG_QUEUE_SIZE 1024 * 1024 * 1

static int remove_queue(int qid)
{
	int ret = -1;
	struct msqid_ds ds;

	if (msgctl(qid, IPC_STAT, &ds) != -1) {
		ret = msgctl(qid, IPC_RMID, &ds);
	}
	return ret;
}

static int open_queue(key_t keyval, int flags)
{
	int qid;
	struct msqid_ds ds;

	if ((qid = msgget(keyval, flags)) == -1)
		return -1;
	if (flags & ~IPC_CREAT) {
		// increase message queue capacity
		if (msgctl(qid, IPC_STAT, &ds) != -1) {
			ds.msg_qbytes = MSG_QUEUE_SIZE;
			msgctl(qid, IPC_SET, &ds);
		}
	}
	return(qid);
}

static int send_message(int qid, msg_t *qbuf)
{
	int result, length;

	length = sizeof(msg_t) - sizeof(long);

	if ((result = msgsnd(qid, qbuf, length, 0)) == -1)
		return -1;
	return result;
}

static int recv_message(int qid, long type, msg_t *qbuf)
{
	int result, length;

	length = sizeof(msg_t) - sizeof(long);

	if ((result = msgrcv(qid, qbuf, length, type, 0)) == -1)
		return -1;
	return result;
}

//
static int g_qid = -1;
static msg_t msg;

int remove_gconf_queue()
{
	int ret = -1;

	if (g_qid != -1)
		ret = remove_queue(g_qid);
	return ret;
}

int send_gconf_msg(int cmd, msg_t *qbuf)
{
	key_t msgkey;

	if (g_qid == -1) {
		msgkey = ftok(FTOK_PATH, 1);
		g_qid = open_queue(msgkey, 0);
		if (g_qid == -1)
			return -1;
	}
	if (qbuf == NULL) {
		msg.mtype = MSG_TYPE;
		msg.pid = getpid();
		msg.cmd = cmd;
		qbuf = &msg;	
	} else
		qbuf->mtype = MSG_TYPE;
	return send_message(g_qid, qbuf);
}

int recv_gconf_msg(msg_t *qbuf, int *valid)
{
	key_t msgkey;
	int ret;

	if (g_qid == -1) {
		msgkey = ftok(FTOK_PATH, 1);
		g_qid = open_queue(msgkey, IPC_CREAT | 0622);
		if (g_qid == -1)
			return -1;
	}
	ret = recv_message(g_qid, 0, qbuf);
	if (ret != -1) {
		if (qbuf->mtype == MSG_TYPE)
			*valid = 1;
		else
			*valid = 0;
	}
	return ret;
}

