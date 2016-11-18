/*
 * Utility to test the functionality of libgconf_hook
 */
/*
 * Copyring (C) 2016 Zhen Huang
 */
#define GCONF_ENABLE_INTERNALS
#include <dlfcn.h>
#include <gconf/gconf-client.h>
#include <gconf/gconf.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include "../kernel_logger/gconf_msg.h"

int main(int argc, char *argv[]) {
	GConfValue *value;
	char buf[VALUE_LEN];
	char *ikey = "/apps/evolution/mail/trash/empty_on_exit_days";
	char *bkey = "/apps/evolution/mail/trash/empty_on_exit";
	char *skey = "/apps/evolution/mail/default_account";
	char *lkey = "/apps/evolution/mail/accounts";
	int oldvalue;
	int newvalue;
	gboolean bvalue;
	gchar *str;

	gconf_init(argc, argv, NULL);
	g_type_init();

	GConfEngine *engine = gconf_engine_get_default();
	value = gconf_value_new(GCONF_VALUE_BOOL);
	if (value) {
		gconf_value_set_bool(value, 0);
		gconf_engine_set(engine, bkey, value, NULL);
	} else
		fprintf(stderr, "Out of memory!\n");

	GConfClient *client = gconf_client_get_default();
	oldvalue = (int)gconf_client_get_int(client, ikey, NULL);
	newvalue = oldvalue * 2;
	gconf_client_set_int(client, ikey, newvalue, NULL);
	bvalue = gconf_client_get_bool(client, bkey, NULL);
	bvalue = !bvalue;
	gconf_client_set_bool(client, bkey, bvalue, NULL);
	str = gconf_client_get_string(client, skey, NULL);
	gconf_client_set_string(client, skey, str, NULL);
	gconf_client_get_list(client, lkey, GCONF_VALUE_STRING, NULL);

	return 0;
}

