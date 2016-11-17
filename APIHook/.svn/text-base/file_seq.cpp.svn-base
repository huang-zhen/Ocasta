#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif // WIN32
#include <stdio.h>
#include <string.h>
#include "file_seq.h"

int
log_seqno(const char *dirname, const char *type, char *filename, int len)
{
	char seqfilename[80];
	int seq_fd;
	int ret = 0;

#ifdef WIN32
	_snprintf(seqfilename, len, "%s\\%s.seqno", dirname, type);
#else
	snprintf(seqfilename, len, "%s/%s.seqno", dirname, type);
#endif
	seqfilename[len - 1] = '\0';
	seq_fd = _open(seqfilename, O_WRONLY | O_CREAT | O_TRUNC,
                          S_IREAD | S_IWRITE);
	if (seq_fd > 0) {
		if (_write(seq_fd, filename, strlen(filename)) != strlen(filename))
			ret = -2;
		_close(seq_fd);	
	} else
		ret = -1;
	return ret;
}

int
open_file_seq(const char *dirname, const char *ext, int max_seq, int *seq_no, char *filename, int len, int flags)
{
	static char* filename_patterns_ext[] = {"%s\\%04d%02d%02d%03d.%s", "%s.%04d%02d%02d%03d.%s"};
	static char* filename_patterns_noext[] = {"%s\\%04d%02d%02d%03d", "%s.%04d%02d%02d%03d"};
	static int num_filename_patterns = sizeof(filename_patterns_ext)/sizeof(char*);
	time_t cur_time;
	struct tm *cur_tm;
	struct stat st;
	int avail = 0, out_fd = -1;

	if (flags < 0 || flags >= num_filename_patterns)
		return -2;

	cur_time = time(NULL);
	cur_tm = localtime(&cur_time);
	// always starts from 1 as the seq_no is meaningless when
	// the current date is different than the one when we were started
	*seq_no = 1;
	do {
		if (ext) {
#ifdef WIN32
		_snprintf(filename, len, filename_patterns_ext[flags], dirname,
#else
		snprintf(filename, len, filename_patterns_ext[flags], dirname,
#endif
			cur_tm->tm_year + 1900,
			cur_tm->tm_mon + 1,
			cur_tm->tm_mday, 
			*seq_no,
			ext);
		} else {
#ifdef WIN32
		_snprintf(filename, len, filename_patterns_noext[flags], dirname,
#else
		snprintf(filename, len, filename_patterns_noext[flags], dirname,
#endif
			cur_tm->tm_year + 1900,
			cur_tm->tm_mon + 1,
			cur_tm->tm_mday, 
			*seq_no);
		}
		filename[len - 1] = '\0';
		if (stat(filename, &st) == -1) {
			avail = 1;
			break;
		}
		(*seq_no) ++;
	} while ((*seq_no) < max_seq);
	if (avail)
#ifdef WIN32
			out_fd = _open(filename, _O_WRONLY | _O_CREAT | _O_TRUNC, _S_IREAD | _S_IWRITE);
#else
        	out_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, S_IREAD | S_IWRITE);
#endif
        return out_fd;
}

