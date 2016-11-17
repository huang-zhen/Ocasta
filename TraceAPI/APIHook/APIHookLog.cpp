#include "stdafx.h"
#include "RealReadLog.h"
#include "io.h"

CRealReadLog::CRealReadLog(char *pathName)
{
  char *logPathName;
  int logPathNameLen;

  if (pathName == NULL) return;
  logPathNameLen = strlen(pathName) + strlen(logFileName);
  logPathName = new char[logPathNameLen + 1];
  strcpy(logPathName, pathName);
  strcat(logPathName, logFileName);
  if (access(logPathName, 0) != -1) m_fileExisted = TRUE;
  else m_fileExisted = FALSE;
  m_logFile = fopen(logPathName, "a"); // creat file if not exist
  delete[] logPathName;
}

CRealReadLog::~CRealReadLog()
{
  if (m_logFile != NULL)
    fclose(m_logFile);
}

BOOL CRealReadLog::Installed()
{
  return m_fileExisted;
}

int CRealReadLog::Output(char *fmt, ...)
{
  if (m_logFile == NULL) return -1;
  int charNum;
  va_list args;
  va_start(args, fmt);
  CTime curTime = CTime::GetCurrentTime();
  charNum = fprintf(m_logFile, curTime.Format("%Y/%m/%d %H:%M:%S\t"));
  charNum += vfprintf(m_logFile, fmt, args);
  va_end(args);
  return charNum;
}

