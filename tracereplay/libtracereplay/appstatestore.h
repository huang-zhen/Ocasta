// appstatestore.h
#ifndef APPSTATE_STORE_H
#define APPSTATE_STORE_H

#include <vector>
#ifdef WIN32
#include <windows.h>
#else
#include "../../testandset/tas.h"
#endif
#include <vector>
#include <string>

class AppStateStore {
public:
	AppStateStore();
	~AppStateStore();
	int init(const char *server);
	int selectdb(int db);
	void settraceid(const char *trace, int id);
	int	gettraceid(const char *trace);
	void settrace(const char *trace);
	void cleandb();
	int gettraces(std::vector<std::string>& traces);
	int getid(const char *trace);
	int setid(const char *trace, int id);
	int setstagekeys(const char *appname, const char *stage);
	int diffstagekeys(const char *appname, const char *keyname, const char *srcstage, const char *deststage, std::vector<std::string>& keys);
	int movekeys(const char *appname, int srcdb, int destdb);
	// methods for replay
	int startproc(const char *appname, const char *pid, double timestamp);
	int exitproc(const char *appname, const char *pid, double timestamp);
	int accesskey(const char *appname, const char *pid, const char *key, double timestamp);
	int updatekey(const char *appname, const char *pid, const char *key, double timestamp);
	int createkey(const char *appname, const char *pid, const char *key, double timestamp);
	int deletekey(const char *appname, const char *pid, const char *key, double timestamp);
	int createproc(const char *appname, const char *pid, const char *childapp, const char *childpid, double timestamp);
	int flush();
	// methods for query
	int getapp(std::vector<std::string>& apps);
	int getproc(const char *appname, std::vector<std::string>& pids);
	int getaccessedkeys(const char *appname, const char *pid, std::vector<std::string>& keys);
	int getupdatedkeys(const char *appname, const char *pid, std::vector<std::string>& keys);
	int getdeletedkeys(const char *appname, const char *pid, std::vector<std::string>& keys);
	int getnumberaccess(const char *appname, const char *pid);
	int getnumberupdate(const char *appname, const char *pid);
	int getnumberdelete(const char *appname, const char *pid);
	double getexecutiontime(const char *appname, const char *pid);
	int getchildproc(const char *appname, const char *pid, std::vector<std::string> children);
	double getstarttime(const char *appname, const char *pid);
	double getendtime(const char *appname, const char *pid);
private:
	void lock();
	void unlock();
	int setstarttime(const char *appname, const char *pid, double timestamp);
	int setendtime(const char *appname, const char *pid, double timestamp);
	int addkey(const char *key);
#ifdef WIN32
	CRITICAL_SECTION sect;
#else
	int mutex;
#endif
	const char *trace;
	struct handle;
	handle *connection;
};
#endif
