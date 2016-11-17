#ifndef FILE_SEQ_H
#define FILE_SEQ_H

// log_seqno: write filename into {dirname}/{type}.seqno
// returns 0 on success
int log_seqno(const char *dirname, const char *type, char *filename, int len);

// open_file_seq: finds an used filename and stores the filename; 
// returns a handle (>= 0) to the file on success
// flags: 0 - uses {dirname}/{date}{seq}[.{ext}] as the pattern for filename
//		  1 - uses {dirname}.{date}{seq}[.{ext}] as the pattern for filename
int open_file_seq(const char *dirname, const char *ext, int max_seq, int *seq_no, char *filename, int len, int flags);
#endif
