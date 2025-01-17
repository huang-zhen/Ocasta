// replay.cpp
#include <string>
#include <iostream>
#include <fstream>
#include <strstream>
#include <set>
#include <map>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "replay.h"
using namespace std;

const int max_buf_size = 512;

const char *Replayer::getappname(const char *pid, const char *thread, double timestamp)
{
	if (appname.find(pid) == appname.end()) {
		if (thread[0] == '(') {
			char buf[max_buf_size];
			strcpy(buf, thread);
			buf[strlen(buf) - 1] = '\0';
			memmove(buf, buf + 1, strlen(buf));
			appname[pid] = buf;
			appstore->startproc(buf, pid, timestamp);
			lastaccesstime[pid] = timestamp;
			exitproctime[pid] = 0;
		}
else {
			appname[pid] = filename;
			lastaccesstime[pid] = timestamp;
		}
	}
	return appname[pid].c_str();
}

char* Replayer::getdoublequotedstring(istream& s, char *value, int removequote)
{
	char buf[1024];
	buf[0] = '\0';
	s >> buf;
	// allow string not enclosed with quotes
	if (buf[0] != '"') {
		strcpy(value, buf);
		return value;
	}
	s.seekg(-(int)strlen(buf), ios::cur);
	if (!removequote)
		strcpy(value, "\"");
	else
		value[0] = '\0';
	int first = 1;
	while (1) {
		if (getquotedstring(s, buf, 0)) {
			if (buf[0] == '\0')
				break;
			if (!first)
				strcat(value, " ");
			else
				first = 0;
			strcat(value, buf);
		} else
			return NULL;
	}
	if (!removequote)
		strcat(value, "\"");
	//value[strlen(value) - 1] = '\0';
	//memmove(value, value + 1, strlen(value));
	return value;
}

char* Replayer::getquotedstring(istream& s, char *value, int removequote)
{
	char buf[1024];
	buf[0] = '\0';
	s >> buf;
	// allow string not enclosed with quotes
	if (buf[0] != '"') {
		strcpy(value, buf);
		return value;
	}
	value[0] = '\0';
	while (1) {
		strcat(value, buf);
		if (buf[strlen(buf) - 1] == '"')
			break;
		strcat(value, " ");
		buf[0] = '\0';
		s >> buf;
		if (buf[0] == '\0')
			return NULL;
	}
	if (removequote) {
		value[strlen(value) - 1] = '\0';
		memmove(value, value + 1, strlen(value));
	}
	return value;
}

const char *Replayer::getbasename(const char *pathname)
{
	const char *tok = NULL;

	tok = strrchr(pathname, '\\');
	if (tok == NULL)
		tok = pathname;
	else
		tok ++;
	return tok;
}

int Replayer::regopenkey(istream &s, double timestamp, const char * pid, const char *thread) {
	int ret;
	s >> ret;
	if (ret == 0) {
		char key[max_buf_size];
		s >> key;
		char value[1024];
		if (!getquotedstring(s, value))
			goto error;
		char handle[max_buf_size];
		handle[0] = '\0';
		s >> handle;
		if (handle[0] == '\0')
			goto error;
		string fullkey = keyhandle->get_opened_key(pid, key);
		if (fullkey != "") {
			if (value[0] != '\0' && strcmp(value, "(null)")) {
				fullkey += "\\";
				fullkey += value;
			}
			keyhandle->set_opened_key(pid, handle, fullkey);
		} else
			return 2;
	} else
		return 3;
	return 0;
error:
	return 1;
}

int Replayer::regqueryvalue(istream &s, double timestamp, const char * pid, const char *thread) {
	int ret;
	s >> ret;
	if (ret == 0) {
		char key[max_buf_size];
		s >> key;
		char value[1024];
		if (!getquotedstring(s, value))
			goto error;
		int type;
		s >> type;
		char data[1024];
		s >> data;
		string fullkey = keyhandle->get_opened_key(pid, key);
		if (fullkey != "") {
			// get fullkey + \ + value == data
			if (value[0] != '\0' && strcmp(value, "(null)")) {
				fullkey += "\\";
				fullkey += value;
			}
			ttstore->get_value(fullkey.c_str(), -1, NULL, NULL, NULL, NULL, timestamp);
			appstore->accesskey(getappname(pid, thread, timestamp), pid, fullkey.c_str(), timestamp);
		} else
			return 2;
	} else
		return 3;
	return 0;
error:
	return 1;
}

int Replayer::regsetvalue(istream &s, double timestamp, const char * pid, const char *thread) {
	int ret;
	s >> ret;
	if (ret == 0) {
		char key[max_buf_size];
		s >> key;
		int type;
		s >> type;
		char temp[1024];
		s >> temp;
		int size;
		char value[1024];
		if (temp[0] == '"') {
			size = type;
			s.seekg(-(int)strlen(temp), ios::cur);
			if (!getquotedstring(s, value))
				goto error;
			s >> type;
		} else {
			size = atoi(temp);
			if (!getquotedstring(s, value))
				goto error;
		}
		char *data = NULL;
		char buf[1024];
		int idata = 0;
		buf[0] = '\0';
		if (type == 4) {
			s >> buf;
			idata = atoi(buf);
			data = (char *)&idata;
			size = sizeof(int); // size is incorrect for some event
		}
		else if (type == 1 || type == 2) {
			//s >> data;
			//if (data[0] == '"') {
				// seekg seems to fail when thes stream is already at its end
				//s.seekg(-(int)strlen(data), ios::cur);
				if (!getquotedstring(s, buf))
					goto error;
				data = buf;
			//}
		} else {
			data = new char[size];
		}
		string fullkey = keyhandle->get_opened_key(pid, key);
		if (fullkey != "") {
			// set fullkey + \ + value= data
			if (value[0] != '\0' && strcmp(value, "(null)")) {
				fullkey += "\\";
				fullkey += value;
			}
			ttstore->set_value(fullkey.c_str(), data, size, type, timestamp);
			appstore->updatekey(getappname(pid, thread, timestamp), pid, fullkey.c_str(), timestamp);
			if (data && data != buf && data != (char *)&idata)
				delete[] data;
		} else {
			if (data && data != buf && data != (char *)&idata)
				delete[] data;
			return 2;
		}
	} else
		return 3;
	return 0;
error:
	return 1;
}

int Replayer::regclosekey(istream &s, double timestamp, const char * pid, const char *thread) {
	int ret;
	s >> ret;
	if (ret == 0) {
		char key[max_buf_size];

		s >> key;
		keyhandle->close_opened_key(pid, key);
		lastaccesstime[pid] = timestamp;
	} else
		return 3;
	return 0;
}

int Replayer::regcreatekey(istream &s, double timestamp, const char * pid, const char *thread) {
	int ret;
	s >> ret;
	if (ret == 0) {
		char key[max_buf_size];
		s >> key;
		char value[1024];
		if (!getquotedstring(s, value))
			goto error;
		char handle[max_buf_size];
		handle[0] = '\0';
		s >> handle;
		if (handle[0] == '\0')
			goto error;
		string fullkey;
		fullkey = keyhandle->get_opened_key(pid, key);
		if (fullkey != "") {
			if (value[0] != '\0' && strcmp(value, "(null)")) {
				fullkey += "\\";
				fullkey += value;
			}
			keyhandle->set_opened_key(pid, handle, fullkey);
		} else
			return 2;
		// create fullkey
		ttstore->create_key(fullkey.c_str(), timestamp);
		//appstore->createkey(getappname(pid, thread, timestamp), pid, fullkey.c_str(), timestamp);
	} else
		return 3;
	return 0;
error:
	return 1;
}

int Replayer::reggetvalue(istream &s, double timestamp, const char * pid, const char *thread) {
	int ret;
	s >> ret;
	if (ret == 0) {
		char key[max_buf_size];
		s >> key;
		char subkey[1024];
		if (!getquotedstring(s, subkey))
			goto error;
		char value[1024];
		if (!getquotedstring(s, value))
			goto error;
		string fullkey;
		fullkey = keyhandle->get_opened_key(pid, key);
		if (fullkey == "")
			return 2;
		if (subkey[0] != '\0' && strcmp(value, "(null)")) {
			fullkey += "\\";
			fullkey += subkey;
		}
		if (value[0] != '\0' && strcmp(value, "(null)")) {
			fullkey += "\\";
			fullkey += value;
		}
		// get fullkey
		ttstore->get_value(fullkey.c_str(), -1, NULL, NULL, NULL, NULL, timestamp);
		appstore->accesskey(getappname(pid, thread, timestamp), pid, fullkey.c_str(), timestamp);
	} else
		return 3;
	return 0;
error:
	return 1;
}

double Replayer::convert_time(char *date, char *time)
{
	struct tm tm;

	int seq = 0;
	int msec = 0;
	char *tok = NULL;

	memset(&tm, 0, sizeof(tm));
	tok = strtok(date, "-");
	seq = 0;
	while (tok) {
		switch (seq) {
			case 0: tm.tm_year = atoi(tok) - 1900;
				break;
			case 1: tm.tm_mon = atoi(tok) - 1;
				break;
			case 2: tm.tm_mday = atoi(tok);
				break;
		}
		tok = strtok(NULL, "-");
		seq++;
	}
	if (seq != 3)
		goto error;
	tok = strtok(time, ":.");
	seq = 0;
	while (tok) {
		switch (seq) {
			case 0: tm.tm_hour = atoi(tok);
				break;
			case 1: tm.tm_min = atoi(tok);
				break;
			case 2: tm.tm_sec = atoi(tok);
				break;
			case 3: msec = atoi(tok);
				break;
		}
		tok = strtok(NULL, ":.");
		seq++;
	}
	if (seq != 4)
		goto error;
	return (double)mktime(&tm) + (double)msec / 1000;
error:
	return 0.0;
}

int Replayer::null(istream &s, double timestamp, const char * pid, const char *thread) {
	return 0;
}

int Replayer::processstart(istream &s, double timestamp, const char * pid, const char *thread) {
	char args[1024], cmd[1024];

	if (getdoublequotedstring(s, args)) {
		istrstream ss(args);
		if (getquotedstring(ss, cmd)) {
			if (cmd[0] == '\0' && thread[0] == '(') {
				char buf[max_buf_size];
				strcpy(buf, thread);
				buf[strlen(buf) - 1] = '\0';
				memmove(buf, buf + 1, strlen(buf));
				appname[pid] = buf;
			} else if (cmd[0] != '\0')
				appname[pid] = getbasename(cmd);
			else
				appname[pid] = filename;
			appstore->startproc(appname[pid].c_str(), pid, timestamp);
			lastaccesstime[pid] = timestamp;
			exitproctime[pid] = 0;
			return 0;
		}
	}
	return 1;
}

int Replayer::processexit(istream &s, double timestamp, const char * pid, const char *thread) {
	keyhandle->close_all_keys(pid);
	appstore->exitproc(getappname(pid, thread, timestamp), pid, timestamp);
	exitproctime[pid] = timestamp;
	return 0;
}

int Replayer::regdeletevalue(istream &s, double timestamp, const char * pid, const char *thread) {
	int ret;
	s >> ret;
	if (ret == 0) {
		char key[max_buf_size];
		s >> key;
		char value[1024];
		if (!getquotedstring(s, value))
			goto error;
		string fullkey;
		fullkey = keyhandle->get_opened_key(pid, key);
		if (fullkey != "") {
			// delete fullkey + \ + value
			if (value[0] != '\0' && strcmp(value, "(null)")) {
				fullkey += "\\";
				fullkey += value;
			}
			ttstore->delete_key(fullkey.c_str(), timestamp);
			appstore->deletekey(getappname(pid, thread, timestamp), pid, fullkey.c_str(), timestamp);
		} else
			return 2;
	} else
		return 3;
	return 0;
error:
	return 1;
}

int Replayer::regdeletekey(istream &s, double timestamp, const char * pid, const char *thread) {
	int ret;
	s >> ret;
	if (ret == 0) {
		char key[max_buf_size];
		s >> key;
		char subkey[1024];
		if (!getquotedstring(s, subkey))
			goto error;
		string fullkey;
		fullkey = keyhandle->get_opened_key(pid, key);
		if (fullkey != "") {
			// delete fullkey + \ + subkey + \ + *
			if (subkey[0] != '\0' && strcmp(subkey, "(null)")) {
				fullkey += "\\";
				fullkey += subkey;
			}
			ttstore->delete_key(fullkey.c_str(), timestamp);
			appstore->deletekey(getappname(pid, thread, timestamp), pid, fullkey.c_str(), timestamp);
		} else
			return 2;
	} else
		return 3;
	return 0;
error:
	return 1;
}

int Replayer::regopencurrentuser(istream &s, double timestamp, const char * pid, const char *thread) {
	int ret;
	s >> ret;
	if (ret == 0) {
		char key[max_buf_size];
		if (!getquotedstring(s, key))
			goto error;
		char handle[max_buf_size];
		handle[0] = '\0';
		s >> handle;
		if (handle[0] == '\0')
			goto error;
		keyhandle->set_opened_key(pid, handle, key);
	} else
		return 3;
	return 0;
error:
	return 1;
}

int Replayer::reguserclassesroot(istream &s, double timestamp, const char * pid, const char *thread) {
	int ret;
	s >> ret;
	if (ret == 0) {
		char key[max_buf_size];
		if (!getquotedstring(s, key))
			goto error;
		char handle[max_buf_size];
		handle[0] = '\0';
		s >> handle;
		if (handle[0] == '\0')
			goto error;
		keyhandle->set_opened_key(pid, handle, key);
	} else
		return 3;
	return 0;
error:
	return 1;
}

int Replayer::createproc(std::istream &s, double timestamp, const char * pid, const char *thread)
{
	char childpid[max_buf_size];
	s >> childpid;
	char childthread[max_buf_size];
	s >> childthread;
	char childapp[1024];
	childapp[0] = '\0';
	s >> childapp;
	if (childapp[0] == '\0')
		goto error;
	appstore->createproc(getappname(pid, thread, timestamp), pid, childapp, childpid, timestamp);
	return 0;
error:
	return 1;
}

Replayer::cmd_dispatch Replayer::dispatchers[] = {
	"HandleDebugEvent", &Replayer::null,
	"OpenHookLib", &Replayer::null,
	"CloseHookLib", &Replayer::null,
	"DetourAPI", &Replayer::null,
	"HookAllAPI", &Replayer::null,
	"UnHookAllAPI", &Replayer::null,
	"InjectProcess", &Replayer::null,
	"RegEnumKeyExA", &Replayer::null,
	"RegEnumKeyExW", &Replayer::null,
	"RegNotifyChangeKeyValue", &Replayer::null,
	"DLL_PROCESS_DETACH", &Replayer::processexit,
	"DLL_PROCESS_ATTACH", &Replayer::processstart,
	"RegOpenKeyExW", &Replayer::regopenkey,
	"RegOpenKeyExA", &Replayer::regopenkey,
	"RegQueryValueExW", &Replayer::regqueryvalue,
	"RegQueryValueExA", &Replayer::regqueryvalue,
	"RegCloseKey", &Replayer::regclosekey,
	"RegSetValueExW", &Replayer::regsetvalue,
	"RegSetValueExA", &Replayer::regsetvalue,
	"RegCreateKeyExW", &Replayer::regcreatekey,
	"RegCreateKeyExA", &Replayer::regcreatekey,
	"RegGetValueW", &Replayer::reggetvalue,
	"RegGetValueA", &Replayer::reggetvalue,
	"RegDeleteValueA", &Replayer::regdeletevalue,
	"RegDeleteValueW", &Replayer::regdeletevalue,
	"RegDeleteKeyExW", &Replayer::regdeletekey,
	"RegDeleteKeyExA", &Replayer::regdeletekey,
	"RegDeleteKeyA", &Replayer::regdeletekey,
	"RegDeleteKeyW", &Replayer::regdeletekey,
	"RegOpenCurrentUser", &Replayer::regopencurrentuser,
	"RegOpenUserClassesRoot", &Replayer::reguserclassesroot,
	"CreateProcThread", &Replayer::createproc,
};

void Replayer::replayline(const char *line)
{
	char buf[1024];
	static double lasttimestamp = 0.0;

	if (line[0] != '#') {
		const char *tok = strstr(line, "RegSetValueExA");
		int fixdone = 0;
		if (tok) {
			// fix a problem that a space is missing between a name and the MD5checksum of its value
			tok = strrchr(line, '"');
			if (tok) {
				if (*(tok + 1) != ' ' && *(tok + 1) != '\0') {
					int len = tok - line + 1;
					memcpy(buf, line, len);
					buf[len] = ' ';
					memcpy(&buf[len + 1], tok + 1, strlen(line) + 1 - len);
					fixdone = 1;
				}
			}
		}
		if (!fixdone)
			strcpy(buf, line);
		istrstream s(buf);
		char date[max_buf_size], time[max_buf_size], pid[max_buf_size], thread[max_buf_size], command[max_buf_size];
		s >> date >> time >> pid >> thread >> command;
		// check very early format of trace
		if (strlen(date) < 10) {
			char temp[max_buf_size];

			strcpy(temp, pid);
			strcpy(pid, date);
			strcpy(date, time);
			strcpy(time, temp);
		}

		int error = 0;
		double timestamp = 0.0;
		if (pid[0] == '\0' || thread[0] == '\0')
			error = 1;
		else {
			timestamp = convert_time(date, time);
			if (timestamp <= 0.0) {
				if (lasttimestamp > 0)
					timestamp = lasttimestamp;
				else
					error = 1;
			} else
				lasttimestamp = timestamp;
		}
		if (!error) {
			// check if we are handling old trace format
			if (thread[0] != '0' || thread[1] != 'x') {
				if (thread[0] != '(') {
					strcpy(command, thread);
					strcpy(thread, "0");
				}
			}
			bool dispatched = false;
			for (int i = 0; i < sizeof(dispatchers) / sizeof(cmd_dispatch); i++) {
				if (dispatchers[i].command == command || dispatchers[i].command + "*" == command) {
					switch ((this->*dispatchers[i].handler)(s, timestamp, pid, thread)) {
						case 1:
							error_lines ++;
							cerr << "Error at line " << lines << endl << line << endl;
							break;
						case 2:
							keynotfound_lines ++;
							break;
						case 3:
							ignored_lines ++;
							break;
					}
					dispatched = true;
					break;
				}
			}
			if (!dispatched) {
				if (unknown_cmds.find(command) == unknown_cmds.end())
					unknown_cmds[command] = 0;
				else
					unknown_cmds[command] ++;
				unknown_lines ++;
			}
		} else {
			error_lines ++;
			cerr << "Invalid line " << lines << endl << line <<endl;
		} 
	}
}

void Replayer::replayfile(const char *tracename, const char* filename)
{
	strncpy(trace, tracename, sizeof(trace));
	ifstream ifs(filename);

	if (ifs.good()) {
		char buf[512];
		strcpy(buf, filename);
		char *tok = strtok(buf, ".");
		int i = 0;
		while (tok) {
			switch(i) {
			case 0:
				break;
			case 1:
				strcpy(this->filename, tok);
				break;
			case 2:
				strcat(this->filename, ".");
				strcat(this->filename, tok);
				break;
			default:
				break;	
			}
			i++;
			tok = strtok(NULL, ".");
		}
			
		cerr << "Replay " << tracename << ": " << filename << endl;
		ttstore = new TimeTravelStore();
		if (ttstore == NULL) {
			cerr << "Error creating TimeTravelStore" << endl;
			return;
		}
		if (ttstore->init("127.0.0.1")) {
			cerr << "Error initializing TimeTravelStore" << endl;
			return;
		}
		keyhandle = new KeyHandle();
		if (keyhandle == NULL) {
			cerr << "Error creating KeyHandle" << endl;
			return;
		}
		appstore = new AppStateStore();
		if (appstore == NULL) {
			cerr << "Error creating AppStateStore" << endl;
			return;
		}
		if (appstore->init("127.0.0.1")) {
			cerr << "Error initializing AppStateStore" << endl;
			return;
		}
		appstore->settrace(tracename);
#ifdef WIN32
		DWORD replaystart = GetTickCount();
#else
		time_t replaystart = time(NULL);
#endif
		char line[1024];
		while (ifs.getline(line, sizeof(line))) {
			lines++;
			replayline(line);
			if (lines % 10000 == 0)
			//if (lines > 484153)
				cout << "Processed " << lines << " lines" << endl;
		}
#ifdef WIN32
		DWORD replayend = GetTickCount();
#else
		time_t replayend = time(NULL);
#endif
		cerr << "Run time: " << (double)(replayend - replaystart) / 1000 << " seconds" << endl;
		if (lines > 0) {
			// simulate an exitproc when an enclosing exitproc event is missing
			for (std::map<std::string, double>::iterator it = exitproctime.begin(); it != exitproctime.end(); it++) {
				if (it->second == 0) {
					appstore->exitproc(appname[it->first].c_str(), it->first.c_str(), lastaccesstime[it->first]);
				}
			}
			int processed_lines = lines - unknown_lines - keynotfound_lines - error_lines - ignored_lines;
			cerr << "Processed " << processed_lines << " (" << (double)processed_lines/lines * 100 << "%) of " << lines << " lines" << endl;
			if (keynotfound_lines)
				cerr << "Keynotfound: " << (double)keynotfound_lines/lines * 100 << "%" << endl;
			if (error_lines)
				cerr << "Error: " << (double)error_lines/lines * 100 << "%" << endl;
			if (unknown_lines) {
				cerr << "Unknown commands: " << (double)unknown_lines/lines * 100 << "%" << endl;
				for (map<string, int>::iterator it = unknown_cmds.begin(); it != unknown_cmds.end(); it++)
					cerr << "\t" << it->first << ": " << (double)it->second/lines * 100 << "%" << endl;
			}
			if (ignored_lines)
				cerr << "Ignored: " << (double)ignored_lines/lines * 100 << "%" << endl;
		} else
			cerr << "Processed 0 lines" << endl;
		cerr << endl;
		delete appstore;
		delete ttstore;
		delete keyhandle;
	} else
		cerr << "Unable to open " << filename << endl;
}

Replayer::Replayer()
{
	lines = unknown_lines = error_lines = keynotfound_lines = ignored_lines = 0;
	keyhandle = NULL;
	ttstore = NULL;
	appstore = NULL;
	trace[0] = '\0';
	filename[0] = '\0';
}

Replayer::~Replayer()
{
}
