#ifndef LOG_H
#define LOG_H
#include <stdio.h>
#ifdef WIN32
#include <windows.h>
#endif // WIN32

class Log {
public:
	enum {
		MIN_LOG_BUFSIZE = 1024,
		DEFAULT_CAP_SIZE = 1024 * 1024 * 50
	};
  Log(int bufsize, int capsize = DEFAULT_CAP_SIZE);
  ~Log();
  int print(char *format, ...);
  int open(const char *filename);
  void close();
  void flush();
  void setbuffering(int mode);
private:
  void split_file();
  void init_file();
  void print_timestamp(FILE *fp);
  void print_sysinfo(FILE *fp);
  void print_osinfo(FILE *fp);
  int get_appname(char *appName, int len);
  void print_error(FILE *fp, const char *msg, int err);
#ifdef WIN32
  CRITICAL_SECTION m_sect;
  HANDLE m_mutex;
  DWORD m_procId;
#endif
  char *m_buf;
  int m_bufsize;
  int m_capsize;
  char *m_ptr;
  char *m_filename;
  char m_appname[MAX_PATH];
  int m_lasterror;
  int m_flushcount;
  int m_errflushcount;
  int m_flushsize;
  int m_printsize;
  int m_buffering;
};
#endif // LOG_H