/*
 * Copyright (C) 2016 Zhen Huang
 */
#ifdef WIN32
#include <windows.h>
#include <io.h>
#include <tlhelp32.h>
#endif // WIN32
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "file_seq.h"
#include "Log.h"

// Each process should have only one instance of Log
Log::Log(int bufsize, int capsize)
{
	m_procId = GetCurrentProcessId();
	m_appname[0] = '\0';
	get_appname(m_appname, sizeof(m_appname));
	m_bufsize = bufsize;
	m_capsize = capsize;
	// bufsize should be at least of MIN_LOG_BUFSIZE for efficiency
	if (bufsize >= MIN_LOG_BUFSIZE)
		m_buf = new char[bufsize];
	else
		m_buf = NULL;
	m_ptr = m_buf;
	m_filename = NULL;
	m_mutex = INVALID_HANDLE_VALUE;
	m_lasterror = 0;
	m_flushcount = m_errflushcount = m_flushsize = m_printsize = 0;
	m_buffering = 1;
	InitializeCriticalSection(&m_sect);
}

Log::~Log()
{
	close();
	if (m_buf)
		delete[] m_buf;
	if (m_filename)
		delete[] m_filename;
	DeleteCriticalSection(&m_sect);
}

// open: setup a new filename and its associated mutex
// return 1 on success
int Log::open(const char *filename)
{
	if (filename) {
		// disallow ending the filename with '\'
		if (filename[strlen(filename) - 1] == '\\')
			return 0;

		if (m_filename)
			delete[] m_filename;
		m_filename = new char[strlen(filename) + 1];
		if (m_filename) {
			strcpy(m_filename, filename);
			if (m_mutex != INVALID_HANDLE_VALUE)
				CloseHandle(m_mutex);

			char buf[MIN_LOG_BUFSIZE];
			const char *sep = NULL;

			sep = strrchr(m_filename, '\\');
			_snprintf(buf, sizeof(buf), "%s_mutex", sep? sep + 1: m_filename);
#ifdef WIN32
			m_mutex = CreateMutex(NULL, FALSE, buf);
			if (m_mutex != NULL)
				return 1;
			else
				m_lasterror = GetLastError();
#else
			return 1;
#endif
		}
	}
	return 0;
}

void Log::close()
{
	if (m_filename) {
		flush();
		if (m_printsize != m_flushsize)
			print("printed %d bytes logged %d bytes in %d writes\n", m_printsize, m_flushsize, m_flushcount);
		if (m_errflushcount)
			print("failed to log %d times\n", m_errflushcount);
		flush();
		delete[] m_filename;
		m_filename = NULL;
		if (m_mutex != INVALID_HANDLE_VALUE) {
			CloseHandle(m_mutex);
			m_mutex = INVALID_HANDLE_VALUE;
		}
	}
}

void Log::print_error(FILE *fp, const char *msg, int err)
{
	SYSTEMTIME curTime;
	GetLocalTime(&curTime);
	fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d.%03d %d 0x%0X (%s) %s %d\n",
	curTime.wYear, curTime.wMonth, curTime.wDay, curTime.wHour, 
	curTime.wMinute, curTime.wSecond, curTime.wMilliseconds, m_procId, GetCurrentThreadId(), m_appname, msg, err);
}

void Log::flush()
{
  int ret;
  FILE *fp;

  EnterCriticalSection(&m_sect);
  // check if there is content in the buffer
  if (m_ptr > m_buf) {
	  // wait for 1 second(s) at maximum
	  ret = WaitForSingleObject(m_mutex, 1000);
	  switch (ret) {
		case WAIT_OBJECT_0:
			split_file();
			fp = fopen(m_filename, "ab");
			if (fp) {
				if (m_lasterror) {
					print_error(fp, "last error", m_lasterror);
					m_lasterror = 0;
				}
				if (fwrite(m_buf, m_ptr - m_buf, 1, fp) != 1)
					m_lasterror = errno;
				fclose(fp);
				if (!m_lasterror) {
					m_flushcount ++;
					m_flushsize += m_ptr - m_buf;
				} else
					m_errflushcount ++;
			} else {
				m_lasterror = errno;
				m_errflushcount ++;
			}
			ReleaseMutex(m_mutex);
			break;
		default:
			split_file();
			fp = fopen(m_filename, "ab");
			if (fp) {
				print_error(fp, "wait mutex failed", ret);
				if (fwrite(m_buf, m_ptr - m_buf, 1, fp) != 1)
					m_lasterror = errno;
				fclose(fp);
				if (!m_lasterror) {
					m_flushcount ++;
					m_flushsize += m_ptr - m_buf;
				} else
					m_errflushcount ++;
			} else {
				m_lasterror = errno;
				m_errflushcount ++;
			}
			break;
	  }
	  m_ptr = m_buf;
  }
  LeaveCriticalSection(&m_sect);
}

int Log::print(char *format, ...)
{
	// assume length of data per call can fit into buf
	char buf[MIN_LOG_BUFSIZE];
	int len = 0;
	DWORD ret = 0;

	if (m_filename == NULL)
		return 0;

	EnterCriticalSection(&m_sect);

	SYSTEMTIME curTime;
	GetLocalTime(&curTime);
	len = _snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d %d 0x%0X (%s) ", 
		curTime.wYear, curTime.wMonth, curTime.wDay, curTime.wHour, 
		curTime.wMinute, curTime.wSecond, curTime.wMilliseconds, m_procId, GetCurrentThreadId(), m_appname);
	
	va_list marker;
	va_start(marker, format);
	len += vsnprintf(buf + len, sizeof(buf) - len, format, marker);
	va_end(marker);
	buf[sizeof(buf) - 1] = '\0';

	m_printsize += len;

	// check if we use buffering
	if (m_ptr) {
		if (m_buffering) {
			if (m_ptr + len >= m_buf + m_bufsize) {
				flush();
				// m_ptr should be equivalent as m_buf now
			}
			strcpy(m_ptr, buf);
			m_ptr += len;
		} else {
			strcpy(m_buf, buf);
			m_ptr = m_buf + len;
			flush();
		}
	} else {
		split_file();
		FILE* fp = fopen(m_filename, "ab");
		if (fp) {
			if (m_lasterror) {
				print_error(fp, "last error", m_lasterror);
				m_lasterror = 0;
			}
			if (fwrite(buf, len, 1, fp) != 1)
				m_lasterror = errno;
			fclose(fp);
			if (!m_lasterror) {
				m_flushcount ++;
				m_flushsize += len;
			} else
				m_errflushcount ++;
		} else {
			m_lasterror = errno;
			m_errflushcount ++;
		}
	}
	LeaveCriticalSection(&m_sect);
	return len;
}

void Log::split_file()
{
	int seq_no = 1;
	char filename[MAX_PATH];
	int fd = _open(m_filename, _O_RDONLY);
	if (fd >= 0) {
		long size = _lseek(fd, 0, SEEK_END);
		_close(fd);
		if (size >= m_capsize) {
			int fd = open_file_seq(m_filename, NULL, 1000, &seq_no, filename, sizeof(filename), 1);
			if (fd >= 0) {
				_close(fd);
				remove(filename);
				rename(m_filename, filename);
				init_file();
			}
		}
	} else
		init_file();
}

void Log::init_file()
{
	FILE *fp = fopen(m_filename, "ab");
	if (fp) {
		print_timestamp(fp);
		print_sysinfo(fp);
		print_osinfo(fp);
		fclose(fp);
	} else
		m_lasterror = errno;
}

void Log::print_timestamp(FILE *fp)
{
#ifdef WIN32
	SYSTEMTIME curTime;
	GetLocalTime(&curTime);
	fprintf(fp, "# Timestamp %04d-%02d-%02d %02d:%02d:%02d.%03d %d 0x%0X\n",
		curTime.wYear, curTime.wMonth, curTime.wDay, curTime.wHour, 
		curTime.wMinute, curTime.wSecond, curTime.wMilliseconds,  m_procId, GetCurrentThreadId());
#endif
}

typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);

void Log::print_sysinfo(FILE *fp)
{
#ifdef WIN32
   PGNSI pGNSI;
   SYSTEM_INFO siSysInfo;

   // Copy the hardware information to the SYSTEM_INFO structure.
   pGNSI = (PGNSI)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
   if (pGNSI)
	   pGNSI(&siSysInfo);
   else
	   GetSystemInfo(&siSysInfo); 
 
   fprintf(fp, "# ComputerName \"%s\"\n", getenv("COMPUTERNAME"));
   fprintf(fp, "# OEM_ID %d\n", siSysInfo.dwOemId);
   fprintf(fp, "# NumberOfProcessors %d\n", siSysInfo.dwNumberOfProcessors);
   fprintf(fp, "# ProcessorType %d\n", siSysInfo.dwProcessorType);
   fprintf(fp, "# ProcessorArch %d\n", siSysInfo.wProcessorArchitecture);
   fprintf(fp, "# ProcessorLevel %d\n", siSysInfo.wProcessorLevel);
   fprintf(fp, "# ProcessorRevision 0x%0X\n", siSysInfo.wProcessorRevision);
   fprintf(fp, "# PageSize %d\n", siSysInfo.dwPageSize);
   fprintf(fp, "# MinimumApplicationAddress 0x%0X\n", siSysInfo.lpMinimumApplicationAddress); 
   fprintf(fp, "# MaximumApplicationAddress 0x%0X\n", siSysInfo.lpMaximumApplicationAddress);
   fprintf(fp, "# ActiveProcessorMask 0x%0X\n", siSysInfo.dwActiveProcessorMask);
#endif
}

void Log::print_osinfo(FILE *fp)
{
#ifdef WIN32
   OSVERSIONINFOEX osvi;
   BOOL bOsVersionInfoEx = FALSE;

   // Try calling GetVersionEx using the OSVERSIONINFOEX structure.
   // If that fails, try using the OSVERSIONINFO structure.

   ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
   osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

   if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) )
   {
      osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
      if (! GetVersionEx ( (OSVERSIONINFO *) &osvi) ) 
         return;
   }

   fprintf(fp, "# PlatformId %d\n", osvi.dwPlatformId);
   fprintf(fp, "# MajorVersion %d\n", osvi.dwMajorVersion);
   fprintf(fp, "# MinorVersion %d\n", osvi.dwMinorVersion);
   fprintf(fp, "# BuildNumber %d\n", (osvi.dwBuildNumber & 0xFFFF));
   fprintf(fp, "# ServicePack \"%s\"\n", osvi.szCSDVersion);

	// Test for specific product on Windows NT 4.0 SP6 and later.
   if( bOsVersionInfoEx )
   {
	   fprintf(fp, "# ProductType %d\n", osvi.wProductType);
	   fprintf(fp, "# SuiteMask 0x%0X\n", osvi.wSuiteMask);
   }
#endif // WIN32
}

int Log::get_appname(char *appName, int len)
{
#ifdef WIN32
	DWORD pid = GetCurrentProcessId();
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hSnap) {
		MODULEENTRY32 ms;

		ms.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnap, &ms)) {
			strncpy(appName, ms.szModule, len);
			appName[len - 1] = '\0';
		}
		CloseHandle(hSnap);
		return 1;
	}
#endif
	return 0;
}

// mode: 0 turn off buffering
//		 1 turn on buffering
void Log::setbuffering(int mode)
{
	m_buffering = mode;
}
