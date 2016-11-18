/*
 * Copyright (C) 2016 Zhen Huang
 */
#include "../kernel_logger/gconf_msg.h"
#include "../kernel_logger/store_gconf_log.h"

int send_gconf_msg(int cmd, msg_t *qbuf)
{
	return store_gconf_log(qbuf);
}

