#ifndef STORE_GCONF_LOG_H
#define STORE_GCONF_LOG_H

#include "gconf_msg.h"

void set_gconf_log_dir(const char *dir);
int store_gconf_log(msg_t *msg);

#endif

