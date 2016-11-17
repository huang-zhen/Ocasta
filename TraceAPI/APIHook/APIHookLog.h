#ifndef REALREADLOG_H
#define REALREADLOG_H
// RealReadLog.h
//
static const char logFileName[] = "RealRead.log";

class CRealReadLog {
public:
  CRealReadLog(char *pathName);
  ~CRealReadLog();
  BOOL Installed(); // return TRUE when logFile exists
  int Output(char *fmt, ...);
private:
  FILE* m_logFile;
  BOOL m_fileExisted; // set by RealReadLog()
};

#endif // REALREADLOG_H