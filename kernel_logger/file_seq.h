#ifndef FILE_SEQ_H
#define FILE_SEQ_H

int log_seqno(const char *dirname, const char *type, char *filename);
int open_file_seq(const char *dirname, const char *ext, int max_seq, int *seq_no, char *filename);

#endif
