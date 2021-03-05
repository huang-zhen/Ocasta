// appstatestore.cpp
#include <assert.h>
#include <string>
#include <strstream>
#include <string.h>
#include "../../libhiredis/hiredis.h"
#include "../../testandset/tas.h"
#include "appstatestore.h"
using namespace std;

struct AppStateStore::handle {
	int db;
	redisContext *context;
	int hasupdate;
};

AppStateStore::AppStateStore()
{
	connection = NULL;
#ifdef WIN32
	InitializeCriticalSection(&sect);
#else
	mutex = 0;
#endif
	trace = NULL;
}

AppStateStore::~AppStateStore()
{
	if (connection) {
		if (connection->hasupdate > 0)
			flush();
		redisFree(connection->context);
		delete connection;
	}
}

void AppStateStore::lock()
{
#ifdef WIN32
	EnterCriticalSection(&sect);
#else
	tas_mutex_lock(&mutex);
#endif
}

void AppStateStore::unlock()
{
#ifdef WIN32
	LeaveCriticalSection(&sect);
#else
	tas_mutex_unlock(&mutex);
#endif
}

int AppStateStore::init(const char *server)
{
	int ret = -1;

	lock();
	if (!connection) {
		connection = new handle();
		if (connection) {
			connection->db = 0;
			connection->hasupdate = 0;
			connection->context = redisConnect(server, 6379);
			if (!connection->context->err) {
				redisReply *reply = NULL;
				reply = (redisReply *)redisCommand(connection->context, "SELECT 1");
				if (reply) {
					connection->db = 1;
					ret = 0;
				}
			}
		}
	}
	unlock();
	return ret;
}

int AppStateStore::selectdb(int db)
{
    	redisReply *reply = NULL;
	int ret = -1;

	if (db >= 0) {
		reply = (redisReply*)redisCommand(connection->context,"SELECT %d", db);
		if (reply) {
			connection->db = db;
			ret = 0;
		}
	}
	return ret;
}

void AppStateStore::settraceid(const char *trace, int id)
{
	redisReply *reply = NULL;

	lock();
	this->trace = trace;
	reply = (redisReply *)redisCommand(connection->context, "SELECT 0");
	if (reply) {
		freeReplyObject(reply);
		reply = (redisReply *)redisCommand(connection->context, "HSET traces %s %d", trace, id);
		if (reply)
			freeReplyObject(reply);
	}
	reply = (redisReply *)redisCommand(connection->context, "SELECT %d", connection->db);
	if (reply)
		freeReplyObject(reply);
	unlock();
}

int AppStateStore::gettraceid(const char *trace)
{
	redisReply *reply = NULL;

	int id = -1;

	lock();
	this->trace = trace;
	reply = (redisReply *)redisCommand(connection->context, "SELECT 0");
	if (reply) {
		freeReplyObject(reply);
		reply = (redisReply *)redisCommand(connection->context, "HGET traces %s", trace);
		if (reply) {
			freeReplyObject(reply);
		}
	}
	reply = (redisReply *)redisCommand(connection->context, "SELECT %d", connection->db);
	if (reply)
		freeReplyObject(reply);
	unlock();
	return id;
}

void AppStateStore::settrace(const char *trace)
{
	this->trace = trace;
}

int AppStateStore::flush()
{
	redisReply *reply = NULL;
	int ret = -1;

	lock();
	reply = (redisReply *)redisCommand(connection->context,"SAVE");
	if (reply)
		ret = 0;
	unlock();
	return ret;
}

// methods for replay
int AppStateStore::startproc(const char *appname, const char *pid, double timestamp)
{
	redisReply *reply = NULL;
	assert(trace != NULL);
	assert(appname[0] != '\0');
	string listapp(trace);
	listapp += "\\";
	listapp += "listapps";

	lock();
	connection->hasupdate = 1;
	reply = (redisReply *)redisCommand(connection->context,"SADD %s %s", listapp.c_str(), appname);
	if (reply) {
		freeReplyObject(reply);
	}
	string listpid(trace);
	listpid += "\\";
	listpid += appname;
	listpid += "\\";
	listpid += "listpids";
	reply = (redisReply *)redisCommand(connection->context,"SADD %s %s", listpid.c_str(), pid);
	if (reply) {
		freeReplyObject(reply);
	}
	double starttime = getstarttime(appname, NULL);
	if (starttime < 1 || starttime > timestamp)
		setstarttime(appname, NULL, timestamp);
	starttime = getstarttime(appname, pid);
	if (starttime < 1 || starttime > timestamp)
		setstarttime(appname, pid, timestamp);
	unlock();
	return 0;
}

int AppStateStore::exitproc(const char *appname, const char *pid, double timestamp)
{
	assert(trace != NULL);
	lock();
	connection->hasupdate = 1;
	double endtime = getendtime(appname, NULL);
	if (endtime < timestamp)
		setendtime(appname, NULL, timestamp);
	endtime = getendtime(appname, pid);
	if (endtime < timestamp)
		setendtime(appname, pid, timestamp);
	unlock();
	return 0;
}

int AppStateStore::accesskey(const char *appname, const char *pid, const char *key, double timestamp)
{
	redisReply *reply = NULL;
	assert(trace != NULL);
	string keystr(trace);
	keystr += "\\";
	keystr += appname;
	keystr += "\\";
	string listkeys(keystr);
	listkeys += "list_accessed_keys";

	lock();
	connection->hasupdate = 1;
	reply = (redisReply *)redisCommand(connection->context, "SADD %s %b", listkeys.c_str(), key, strlen(key));
	if (reply)
		freeReplyObject(reply);

	keystr += pid;
	keystr += "\\";
	string numaccess(keystr);
	numaccess += "num_access";
	reply = (redisReply *)redisCommand(connection->context, "INCR %s", numaccess.c_str());
	if (reply) {
		freeReplyObject(reply);
		string listkeys(keystr);
		listkeys += "list_accessed_keys";
		reply = (redisReply *)redisCommand(connection->context, "SADD %s %b", listkeys.c_str(), key, strlen(key));
		if (!reply)
			goto error;
		freeReplyObject(reply);
	} else
		goto error;
	unlock();
	return 0;
error:
	unlock();
	return -1;
}

int AppStateStore::updatekey(const char *appname, const char *pid, const char *key, double timestamp)
{
	redisReply *reply = NULL;
	assert(trace != NULL);
	string keystr(trace);
	keystr += "\\";
	keystr += appname;
	keystr += "\\";
	string listkeys(keystr);
	listkeys += "list_updated_keys";

	lock();
	connection->hasupdate = 1;
	reply = (redisReply *)redisCommand(connection->context, "SADD %s %b", listkeys.c_str(), key, strlen(key));
	if (reply)
		freeReplyObject(reply);

	keystr += pid;
	keystr += "\\";
	string numupdate(keystr);
	numupdate += "num_update";
	reply = (redisReply *)redisCommand(connection->context, "INCR %s", numupdate.c_str());
	if (reply) {
		freeReplyObject(reply);
		string listkeys(keystr);
		listkeys += "list_updated_keys";
		reply = (redisReply *)redisCommand(connection->context, "SADD %s %b", listkeys.c_str(), key, strlen(key));
		if (!reply)
			goto error;
		freeReplyObject(reply);
	} else
		goto error;
	unlock();
	return 0;
error:
	unlock();
	return -1;
}

int AppStateStore::createkey(const char *appname, const char *pid, const char *key, double timestamp)
{
	assert(trace != NULL);
	return 0;
}

int AppStateStore::deletekey(const char *appname, const char *pid, const char *key, double timestamp)
{
	redisReply *reply = NULL;
	assert(trace != NULL);
	string keystr(trace);
	keystr += "\\";
	keystr += appname;
	keystr += "\\";
	string listkeys(keystr);
	listkeys += "list_updated_keys";

	lock();
	connection->hasupdate = 1;
	reply = (redisReply *)redisCommand(connection->context, "SADD %s %b", listkeys.c_str(), key, strlen(key));
	if (reply)
		freeReplyObject(reply);

	keystr += pid;
	keystr += "\\";
	string numdelete(keystr);
	numdelete += "num_delete";
	reply = (redisReply *)redisCommand(connection->context, "INCR %s", numdelete.c_str());
	if (reply) {
		freeReplyObject(reply);
		string listkeys(keystr);
		listkeys += "list_deleted_keys";
		reply = (redisReply *)redisCommand(connection->context, "SADD %s %b", listkeys.c_str(), key, strlen(key));
		if (!reply)
			goto error;
		freeReplyObject(reply);
	} else
		goto error;
	unlock();
	return 0;
error:
	unlock();
	return -1;
}

int AppStateStore::createproc(const char *appname, const char *pid, const char *childapp, const char *childpid, double timestamp)
{
	redisReply *reply = NULL;
	assert(trace != NULL);
	string keystr(trace);
	keystr += "\\";
	keystr += appname;
	keystr += "\\";
	keystr += pid;
	keystr += "\\";
	string numchildren(keystr);
	numchildren += "num_children";

	lock();
	connection->hasupdate = 1;
	reply = (redisReply *)redisCommand(connection->context, "INCR %s", numchildren.c_str());
	if (reply) {
		freeReplyObject(reply);
		string listchildren(keystr);
		listchildren += "list_children";
		string child(childapp);
		child += "\\";
		child += childpid;
		reply = (redisReply *)redisCommand(connection->context, "SADD %s %b", listchildren.c_str(), child.c_str(), child.length());
		if (!reply)
			goto error;
		freeReplyObject(reply);
	} else
		goto error;
	unlock();
	return 0;
error:
	unlock();
	return -1;
}

// methods for query
int AppStateStore::getapp(vector<string>& apps)
{
	int ret = -1;
	redisReply *reply = NULL;
	assert(trace != NULL);
	string listpid(trace);
	listpid += "\\";
	listpid += "listapps";

	lock();
	reply = (redisReply *)redisCommand(connection->context,"SCARD %s", listpid.c_str());
	if (reply) {
		ret = reply->integer;
		freeReplyObject(reply);
	} else
		goto bail;
	reply = (redisReply *)redisCommand(connection->context,"SMEMBERS %s", listpid.c_str());
	if (reply) {
		if (reply->type == REDIS_REPLY_ARRAY) {
			apps.clear();
			for (int i = 0; i < reply->elements; i++)
				apps.push_back(reply->element[i]->str);
		}
		freeReplyObject(reply);
	} else
		goto bail;
bail:
	unlock();
	return ret;
}

int AppStateStore::getproc(const char *appname, vector<string>& pids)
{
	int ret = -1;
	redisReply *reply = NULL;
	assert(trace != NULL);
	string listpid(trace);
	listpid += "\\";
	listpid += appname;
	listpid += "\\";
	listpid += "listpids";

	lock();
	reply = (redisReply *)redisCommand(connection->context,"SCARD %s", listpid.c_str());
	if (reply) {
		ret = reply->integer;
		freeReplyObject(reply);
	} else
		goto bail;
	reply = (redisReply *)redisCommand(connection->context,"SMEMBERS %s", listpid.c_str());
	if (reply) {
		if (reply->type == REDIS_REPLY_ARRAY) {
			for (int i = 0; i < reply->elements; i++)
				pids.push_back(reply->element[i]->str);
		}
		freeReplyObject(reply);
	} else
		goto bail;
bail:
	unlock();
	return ret;
}

int AppStateStore::getnumberaccess(const char *appname, const char *pid)
{
	int ret = -1;
	redisReply *reply = NULL;
	assert(trace != NULL);
	string keystr(trace);
	keystr += "\\";
	keystr += appname;
	keystr += "\\";
	keystr += pid;
	keystr += "\\";
	string numaccess(keystr);
	numaccess += "num_access";

	lock();
	reply = (redisReply *)redisCommand(connection->context, "GET %s", numaccess.c_str());
	if (reply) {
		if (reply->type == REDIS_REPLY_INTEGER)
			ret = reply->integer;
		else if (reply->type == REDIS_REPLY_STRING) {
			char *buf = new char[reply->len + 1];
			if (buf) {
				memcpy(buf, reply->str, reply->len);
				buf[reply->len] = '\0';
				istrstream ss(buf);
				ss >> ret;
				delete[] buf;
			}
		} else if (reply->type == REDIS_REPLY_NIL)
			ret = 0;
		freeReplyObject(reply);
	}
	unlock();
	return ret;
}

int AppStateStore::getnumberupdate(const char *appname, const char *pid)
{
	int ret = -1;
	redisReply *reply = NULL;
	assert(trace != NULL);
	string keystr(trace);
	keystr += "\\";
	keystr += appname;
	keystr += "\\";
	keystr += pid;
	keystr += "\\";
	string numaccess(keystr);
	numaccess += "num_update";

	lock();
	reply = (redisReply *)redisCommand(connection->context, "GET %s", numaccess.c_str());
	if (reply) {
		if (reply->type == REDIS_REPLY_INTEGER)
			ret = reply->integer;
		else if (reply->type == REDIS_REPLY_STRING) {
			char *buf = new char[reply->len + 1];
			if (buf) {
				memcpy(buf, reply->str, reply->len);
				buf[reply->len] = '\0';
				istrstream ss(buf);
				ss >> ret;
				delete[] buf;
			}
		} else if (reply->type == REDIS_REPLY_NIL)
			ret = 0;
		freeReplyObject(reply);
	}
	unlock();
	return ret;
}

int AppStateStore::getnumberdelete(const char *appname, const char *pid)
{
	int ret = -1;
	redisReply *reply = NULL;
	assert(trace != NULL);
	string keystr(trace);
	keystr += "\\";
	keystr += appname;
	keystr += "\\";
	keystr += pid;
	keystr += "\\";
	string numaccess(keystr);
	numaccess += "num_delete";

	lock();
	reply = (redisReply *)redisCommand(connection->context, "GET %s", numaccess.c_str());
	if (reply) {
		if (reply->type == REDIS_REPLY_INTEGER)
			ret = reply->integer;
		else if (reply->type == REDIS_REPLY_STRING) {
			char *buf = new char[reply->len + 1];
			if (buf) {
				memcpy(buf, reply->str, reply->len);
				buf[reply->len] = '\0';
				istrstream ss(buf);
				ss >> ret;
				delete[] buf;
			}
		} else if (reply->type == REDIS_REPLY_NIL)
			ret = 0;
		freeReplyObject(reply);
	}
	unlock();
	return ret;
}

int AppStateStore::getaccessedkeys(const char *appname, const char *pid, vector<string>& keys)
{
	int ret = -1;
	redisReply *reply = NULL;
	assert(trace != NULL);
	string listkeys(trace);
	listkeys += "\\";
	listkeys += appname;

	if (pid) {
		listkeys += "\\";
		listkeys += pid;
	}
	listkeys += "\\list_accessed_keys";

	lock();
	reply = (redisReply *)redisCommand(connection->context, "SCARD %s", listkeys.c_str());
	if (reply) {
		ret = reply->integer;
		freeReplyObject(reply);
	} else {
		ret = 0;
		goto bail;
	}
	reply = (redisReply *)redisCommand(connection->context, "SMEMBERS %s", listkeys.c_str());
	if (reply) {
		if (reply->type == REDIS_REPLY_ARRAY) {
			keys.clear();
			for (int i = 0; i < reply->elements; i++)
				keys.push_back(reply->element[i]->str);
		}
		freeReplyObject(reply);
	}
bail:
	unlock();
	return ret;
}

int AppStateStore::getupdatedkeys(const char *appname, const char *pid, vector<string>& keys)
{
	int ret = -1;
	redisReply *reply = NULL;
	assert(trace != NULL);
	string listkeys(trace);
	listkeys += "\\";
	listkeys += appname;
	if (pid) {
		listkeys += "\\";
		listkeys += pid;
	}
	listkeys += "\\list_updated_keys";

	lock();
	reply = (redisReply *)redisCommand(connection->context, "SCARD %s", listkeys.c_str());
	if (reply) {
		ret = reply->integer;
		freeReplyObject(reply);
	} else {
		ret = 0;
		goto bail;
	}
	reply = (redisReply *)redisCommand(connection->context, "SMEMBERS %s", listkeys.c_str());
	if (reply) {
		if (reply->type == REDIS_REPLY_ARRAY) {
			keys.clear();
			for (int i = 0; i < reply->elements; i++)
				keys.push_back(reply->element[i]->str);
		}
		freeReplyObject(reply);
	}
bail:
	unlock();
	return ret;
}

int AppStateStore::getdeletedkeys(const char *appname, const char *pid, std::vector<std::string>& keys)
{
	int ret = -1;
	redisReply *reply = NULL;
	assert(trace != NULL);
	string listkeys(trace);
	listkeys += "\\";
	listkeys += appname;
	if (pid) {
		listkeys += "\\";
		listkeys += pid;
	}
	listkeys += "\\list_deleted_keys";

	lock();
	reply = (redisReply *)redisCommand(connection->context, "SCARD %s", listkeys.c_str());
	if (reply) {
		ret = reply->integer;
		freeReplyObject(reply);
	} else {
		ret = 0;
		goto bail;
	}
	reply = (redisReply *)redisCommand(connection->context, "SMEMBERS %s", listkeys.c_str());
	if (reply) {
		if (reply->type == REDIS_REPLY_ARRAY) {
			keys.clear();
			for (int i = 0; i < reply->elements; i++)
				keys.push_back(reply->element[i]->str);
		}
		freeReplyObject(reply);
	}
bail:
	unlock();
	return ret;
}

double AppStateStore::getexecutiontime(const char *appname, const char *pid)
{
	assert(trace != NULL);

	lock();
	double starttime = getstarttime(appname, pid);
	double endtime = getendtime(appname, pid);
	unlock();
	if (starttime > 0 && endtime > 0)
		return endtime - starttime;
	else
		return 0;
}

int AppStateStore::getchildproc(const char *appname, const char *pid, vector<string> children)
{
	assert(trace != NULL);
	return 0;
}

double AppStateStore::getstarttime(const char *appname, const char *pid)
{
	redisReply *reply = NULL;
	double ret = 0.0;
	assert(trace != NULL);
	string starttime(trace);
	starttime += "\\";
	starttime += appname;
	if (pid) {
		starttime += "\\";
		starttime += pid;
	}
	starttime += "\\start_time";
	reply = (redisReply *)redisCommand(connection->context, "GET %s", starttime.c_str());
	if (reply) {
		if (reply->type == REDIS_REPLY_STRING) {
			memcpy(&ret, reply->str, reply->len);
		}
		freeReplyObject(reply);
	}
	return ret;
}

double AppStateStore::getendtime(const char *appname, const char *pid)
{
	redisReply *reply = NULL;
	double ret = 0.0;
	assert(trace != NULL);
	string starttime(trace);
	starttime += "\\";
	starttime += appname;
	if (pid) {
		starttime += "\\";
		starttime += pid;
	}
	starttime += "\\end_time";
	reply = (redisReply *)redisCommand(connection->context, "GET %s", starttime.c_str());
	if (reply) {
		if (reply->type == REDIS_REPLY_STRING) {
			memcpy(&ret, reply->str, reply->len);
		}
		freeReplyObject(reply);
	}
	return ret;
}

int AppStateStore::setstarttime(const char *appname, const char *pid, double timestamp)
{
	redisReply *reply = NULL;
	int ret = -1;
	assert(trace != NULL);
	string starttime(trace);
	starttime += "\\";
	starttime += appname;
	if (pid) {
		starttime += "\\";
		starttime += pid;
	}
	starttime += "\\start_time";
	reply = (redisReply *)redisCommand(connection->context, "SET %s %b", starttime.c_str(), &timestamp, sizeof(timestamp));
	if (reply) {
		freeReplyObject(reply);
		ret = 0;
	}
	return ret;
}

int AppStateStore::setendtime(const char *appname, const char *pid, double timestamp)
{
	redisReply *reply = NULL;
	int ret = -1;
	assert(trace != NULL);
	string endtime(trace);
	endtime += "\\";
	endtime += appname;
	if (pid) {
		endtime += "\\";
		endtime += pid;
	}
	endtime += "\\end_time";
	reply = (redisReply *)redisCommand(connection->context, "SET %s %b", endtime.c_str(), &timestamp, sizeof(timestamp));
	if (reply) {
		freeReplyObject(reply);
		ret = 0;
	}
	return ret;
}

// convert key to index
// Need to do: how do we atomically increase index and add a new key?
int AppStateStore::addkey(const char *key)
{
#if 0
	redisReply *reply = NULL;
	lock();
	assert(trace != NULL);
	string keystr(trace);
	keystr += "\\";
	//string keylock(keystr);
	//keylock += "lock";
	//keystr += key;
	//reply = (redisReply *)redisCommand(connection->context, "GE
	unlock();
#endif
	return 0;
}

int AppStateStore::setstagekeys(const char *appname, const char *stage)
{
	int ret = -1;
	assert(trace != NULL);
	string appkeys(trace);
	appkeys += "\\\\";
	appkeys += appname;
	appkeys += "\\\\*";

	lock();
	connection->hasupdate = 1;
	redisReply *reply = (redisReply *)redisCommand(connection->context, "KEYS %s", appkeys.c_str());
	vector<string> keys;
	if (reply) {
		ret = 0;
		if (reply->type == REDIS_REPLY_ARRAY) {
			for (int i = 0; i < reply->elements; i++)
				keys.push_back(reply->element[i]->str);
		}
		freeReplyObject(reply);
	}
	for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++) {
		string stagekey(stage);
		stagekey += "\\";
		stagekey += *it;
		reply = (redisReply *)redisCommand(connection->context, "RENAME %s %s", it->c_str(), stagekey.c_str());
		if (reply) {
			ret ++;
			freeReplyObject(reply);
		}
	}
	unlock();
	return ret;
}

int AppStateStore::diffstagekeys(const char *appname, const char *keyname, const char *srcstage, const char *deststage, std::vector<std::string>& keys)
{
	int ret = -1;
	assert(trace != NULL);
	string srcstagekeys(srcstage);
	srcstagekeys += "\\";
	srcstagekeys += trace;
	srcstagekeys += "\\";
	srcstagekeys += appname;
	srcstagekeys += "\\";
	srcstagekeys += keyname;

	string deststagekeys(deststage);
	deststagekeys += "\\";
	deststagekeys += trace;
	deststagekeys += "\\";
	deststagekeys += appname;
	deststagekeys += "\\";
	deststagekeys += keyname;

	lock();
	redisReply *reply = (redisReply *)redisCommand(connection->context, "SDIFF %s %s", srcstagekeys.c_str(), deststagekeys.c_str());
	if (reply) {
		ret = 0;
		if (reply->type == REDIS_REPLY_ARRAY) {
			for (int i = 0; i < reply->elements; i++)
				keys.push_back(reply->element[i]->str);
		}
		freeReplyObject(reply);
	}
	unlock();
	return ret;
}

int AppStateStore::movekeys(const char *appname, int srcdb, int destdb)
{
	int ret = -1;
	assert(trace != NULL);
	string appkeys(trace);
	appkeys += "\\\\";
	appkeys += appname;
	appkeys += "\\\\*";
	redisReply *reply = NULL;

	lock();
	connection->hasupdate = 1;
	reply = (redisReply *)redisCommand(connection->context, "SELECT %d", srcdb);
	if (reply)
		freeReplyObject(reply);
	reply = (redisReply *)redisCommand(connection->context, "KEYS %s", appkeys.c_str());
	vector<string> keys;
	if (reply) {
		ret = 0;
		if (reply->type == REDIS_REPLY_ARRAY) {
			for (int i = 0; i < reply->elements; i++)
				keys.push_back(reply->element[i]->str);
		}
		freeReplyObject(reply);
	}
	for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++) {
		reply = (redisReply *)redisCommand(connection->context, "MOVE %s %d", it->c_str(), destdb);
		if (reply) {
			ret ++;
			freeReplyObject(reply);
		}
	}
	reply = (redisReply *)redisCommand(connection->context, "SELECT %d", connection->db);
	if (reply)
		freeReplyObject(reply);
	unlock();
	return ret;
}

int AppStateStore::gettraces(vector<string>& traces)
{
	int ret = -1;

	lock();
	redisReply *reply = (redisReply *)redisCommand(connection->context, "SELECT 0");
	if (reply) {
		freeReplyObject(reply);
		reply = (redisReply *)redisCommand(connection->context, "HKEYS traces");
		if (reply) {
			if (reply->type == REDIS_REPLY_ARRAY) {
				traces.clear();
				for (int i = 0; i < reply->elements; i++)
					traces.push_back(reply->element[i]->str);
				ret = 0;
			}
			freeReplyObject(reply);
		}
	}
	reply = (redisReply *)redisCommand(connection->context, "SELECT %d", connection->db);
	if (reply)
		freeReplyObject(reply);
	unlock();
	return ret;
}
int AppStateStore::setid(const char *tracename, int id)
{
	int ret = 0;

	if (getid(tracename) > 0)
		return 0;
	lock();
	redisReply *reply = (redisReply *)redisCommand(connection->context, "SELECT 0");
	if (reply) {
		freeReplyObject(reply);
		reply = (redisReply *)redisCommand(connection->context, "HSET traces %s %d", tracename, id);
		if (reply) {
			ret = 0;
			freeReplyObject(reply);
		}
	}
	reply = (redisReply *)redisCommand(connection->context, "SELECT %d", connection->db);
	if (reply)
		freeReplyObject(reply);
	unlock();
	return ret;	
}

int AppStateStore::getid(const char *tracename)
{
	int id = 0;

	lock();
	redisReply *reply = (redisReply *)redisCommand(connection->context, "SELECT 0");
	if (reply) {
		freeReplyObject(reply);
		if (tracename) {
			reply = (redisReply *)redisCommand(connection->context, "HGET traces %s", tracename);
		} else {
			reply = (redisReply *)redisCommand(connection->context, "HLEN traces");
		}
		if (reply) {
			if (reply->type == REDIS_REPLY_INTEGER) {
				id = reply->integer;
			} else if (reply->type == REDIS_REPLY_STRING) {
				char *buf = new char[reply->len + 1];
				if (buf) {
					memcpy(buf, reply->str, reply->len);
					buf[reply->len] = '\0';
					istrstream ss(buf);
					ss >> id;
					delete[] buf;
				}
			}
			freeReplyObject(reply);
		}
	}
	reply = (redisReply *)redisCommand(connection->context, "SELECT %d", connection->db);
	if (reply)
		freeReplyObject(reply);
	unlock();
	return id;	
}

void AppStateStore::cleandb()
{
	redisReply *reply = NULL;

	lock();
	reply = (redisReply *)redisCommand(connection->context, "FLUSHDB");
	if (reply)
		freeReplyObject(reply);
	unlock();
}

