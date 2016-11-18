// ocasta_dat.h
#ifndef OCASTA_DAT_H
#define OCASTA_DAT_H

#define TRACE_DAT_MAJOR		1
#define TRACE_DAT_MINOR 	0
#define TRACE_DAT_FLAG		"TRACE_DAT"
#define TRACE_DAT_FLAG_LEN	9

#pragma pack(1)

struct dat_header {
	char flag[TRACE_DAT_FLAG_LEN];
	unsigned short major;
	unsigned short minor;
	unsigned short rec_size;
};

struct dat_entry {
	int pid;
	int seq_no;
	struct timeval time;
	int path_len;
	size_t file_size;	
};
#endif // OCASTA_DAT_H
