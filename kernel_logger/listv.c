// listv.c
// list file versions

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
    printf("list_version -s filename\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    char *filename = NULL;
    int filec = 1;
    int show_versions = 0;
    int ret;

    if (argc < 2)
	usage();
    if (!strcmp(argv[1], "-s")) {
	show_versions = 1;
	filec ++;
    }
    filename = argv[filec];
    ret = list_version(filename, show_versions);
    //printf("%d\n", ret);
    return ret;
}

