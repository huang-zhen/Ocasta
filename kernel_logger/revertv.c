// revertv.c
// revert a file to a specified version
/*
 * Copyright (C) 2016 Zhen Huang 
*/


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif 
#include "versioning.h"

void usage()
{
    printf("revertv -a|-t time|version filename\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    time_t time;
    int version;
    int argp = 1, ret = 0;
    char *file = NULL;
    char revert_file[MAX_PATH];

    if (argc < 3)
	usage();
    if (strcmp(argv[argp], "-a") == 0) { // all versions
	file = argv[argp + 1];
	for (version = 1; ; version ++) {
		sprintf(revert_file, "%s.%d", file, version);
		ret = revert_version(file, revert_file, version);
		if (!ret)
			break;
	}
    } else if (strcmp(argv[argp], "-t") == 0) { // version at specific time
	time = (time_t)atoi(argv[argp + 1]);
	file = argv[argp + 2];
	sprintf(revert_file, "%s@%d", file, (int)time);
	ret = revert_version_by_time(file, revert_file, time);
	if (!ret)
		printf("Unable to find version at %d\n", (int)time);
    } else {
	version = atoi(argv[argp]);
	file = argv[argp + 1];
	sprintf(revert_file, "%s.%d", file, version);
	ret = revert_version(file, revert_file, version);
	if (!ret)
		printf("Unable to find version %d\n", version);
    }
    return ret;
}
