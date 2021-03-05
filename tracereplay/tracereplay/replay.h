// replay.h
#ifndef REPLAY_H
#define REPLAY_H

#include <map>
#include <string>
#include <iostream>
#include "keyhandle.h"
#ifdef WIN32
#include "appstatestore.h"
#include "timetravelstore.h"
#else
#include "../../timetravelstore/timetravelstore/timetravelstore.h"
#include "../libtracereplay/appstatestore.h"
#endif

class Replayer {
public:
	Replayer();
	~Replayer();
	void replayline(const char *line);
	void replayfile(const char *tracename, const char* filename);
private:
	typedef int (Replayer::*cmd_handler)(std::istream&, double, const char *, const char*);
	struct cmd_dispatch {
		std::string command;
		cmd_handler handler;
	};
	char *getquotedstring(std::istream& s, char *value, int removequote = 1);
	char *getdoublequotedstring(std::istream& s, char *value, int removequote = 1);
	const char *getbasename(const char *pathname);
	const char *getappname(const char *pid, const char *thread, double timestamp);
	int regopenkey(std::istream &s, double timestamp, const char * pid, const char *thread);
	int regqueryvalue(std::istream &s, double timestamp, const char * pid, const char *thread);
	int regsetvalue(std::istream &s, double timestamp, const char * pid, const char *thread);
	int regclosekey(std::istream &s, double timestamp, const char * pid, const char *thread);
	int regcreatekey(std::istream &s, double timestamp, const char * pid, const char *thread);
	int reggetvalue(std::istream &s, double timestamp, const char * pid, const char *thread);
	int null(std::istream &s, double timestamp, const char * pid, const char *thread);
	int processstart(std::istream &s, double timestamp, const char * pid, const char *thread);
	int processexit(std::istream &s, double timestamp, const char * pid, const char *thread);
	int regdeletevalue(std::istream &s, double timestamp, const char * pid, const char *thread);
	int regopencurrentuser(std::istream &s, double timestamp, const char * pid, const char *thread);
	int reguserclassesroot(std::istream &s, double timestamp, const char * pid, const char *thread);
	int regdeletekey(std::istream &s, double timestamp, const char * pid, const char *thread);
	int createproc(std::istream &s, double timestamp, const char * pid, const char *thread);
	double convert_time(char *date, char *time);

	static cmd_dispatch dispatchers[];
	std::map<std::string, int> unknown_cmds;
	int lines;
	int unknown_lines;
	int error_lines;
	int keynotfound_lines;
	int ignored_lines;

	KeyHandle *keyhandle;
	TimeTravelStore *ttstore;
	AppStateStore *appstore;
	char trace[80];
	char filename[512];
	std::map<std::string, std::string> appname;
	std::map<std::string, double> lastaccesstime;
	std::map<std::string, double> exitproctime;
};
#endif
