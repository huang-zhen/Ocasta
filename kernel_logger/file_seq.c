/*
 * Ocasta kernel_logger
 * Copyright (C) 2016 Zhen Huang 
*/

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "file_seq.h"

int
log_seqno(const char *dirname, const char *type, char *filename)
{
	char seqfilename[80];
	int seq_fd;
	int ret = 0;

	sprintf(seqfilename, "%s/%s.seqno", dirname, type);
	seq_fd = open(seqfilename, O_WRONLY | O_CREAT | O_TRUNC,
                          S_IREAD | S_IWRITE);
	if (seq_fd > 0) {
		if (write(seq_fd, filename, strlen(filename)) != strlen(filename))
			ret = -2;
		close(seq_fd);	
	} else
		ret = -1;
	return ret;
}

int
open_file_seq(const char *dirname, const char *ext, int max_seq, int *seq_no, char *filename)
{
	time_t cur_time;
	struct tm *cur_tm;
	struct stat st;
	int avail = 0, out_fd = -1;

	cur_time = time(NULL);
	cur_tm = localtime(&cur_time);
	// always starts from 1 as the seq_no is meaningless when
	// the current date is different than the one when we were started
	*seq_no = 1;
	do {
		sprintf(filename, "%s/%04d%02d%02d%02d.%s", dirname,
			cur_tm->tm_year + 1900,
			cur_tm->tm_mon + 1,
			cur_tm->tm_mday, 
			*seq_no,
			ext);
		if (stat(filename, &st) == -1) {
			avail = 1;
			break;
		}
		(*seq_no) ++;
	} while ((*seq_no) < max_seq);
	if (avail)
        	out_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, S_IREAD | S_IWRITE);
        return out_fd;
}

