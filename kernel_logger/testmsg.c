#include <stdio.h>
#include "gconf_msg.h"

int main() {
	int ret;
	msg_t msg;

	ret = send_gconf_msg(GCONF_SET_VALUE, NULL);
	if (ret == -1)
		perror("send_gconf_msg");
	ret = send_gconf_msg(GCONF_GET_VALUE, NULL);
	if (ret == -1)
		perror("send_gconf_msg");
	ret = send_gconf_msg(GCONF_SET_VALUE, NULL);
	if (ret == -1)
		perror("send_gconf_msg");
	ret = send_gconf_msg(GCONF_GET_VALUE, NULL);
	if (ret == -1)
		perror("send_gconf_msg");
	ret = send_gconf_msg(GCONF_SET_VALUE, NULL);
	if (ret == -1)
		perror("send_gconf_msg");
	ret = send_gconf_msg(GCONF_GET_VALUE, NULL);
	if (ret == -1)
		perror("send_gconf_msg");
/*
	while (1) {
		ret = read_gconf_msg(&msg);
		if (ret == -1) {
			perror("read_gconf_msg");
			break;
		}
		printf("read_gconf_msg:%d\n", msg.cmd);
	}
*/
	return ret;
}
