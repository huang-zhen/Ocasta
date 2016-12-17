// timetravelstore.h
#ifndef TIMETRAVELSTORE_H
#define TIMETRAVELSTORE_H

#include <list>
#include <vector>
#include <map>
#include <string>
#ifdef WIN32
#include <windows.h>
#else
#include "../../libtas/tas.h"
#endif


class TimeTravelStore {
public:
	TimeTravelStore();
	~TimeTravelStore();

#ifndef WIN32
	enum {
		REG_SZ = 1,
		REG_EXPAND_SZ = 2,
		REG_BINARY = 3,
		REG_DWORD = 4,
		REG_UNKNOWN = 5,
	};
#endif
	enum {
		max_key_len = 1024,
		max_value_len = 1024 * 1024,
	};
	struct key_info_t {
		double create_time;
		double last_create_time;
		double last_delete_time;
		double last_set_time;
		long get_count;
		long set_count;
		long delete_count;
		long create_count;
		int set_before_get;
		long current_version;
	};
	struct key_info_t64 {
		double create_time;
		double last_create_time;
		double last_delete_time;
		double last_set_time;
		long long get_count;
		long long set_count;
		long long delete_count;
		long long create_count;
		int set_before_get;
		int padding;
		long long current_version;
	};

	int init(const char *server);
	int selectdb(int db);
	int flush();
	int create_key_ex(const char *key, double timestamp, int flag = 0);
	int delete_key(const char *key, double timestamp, int flag = 0);
	int get_key_info_ex(const char *key, struct key_info_t *info);
	int set_key_info_ex(const char *key, struct key_info_t *info);
	int set_value(const char *key, const char *value, int valuelen, int type, double timestamp, int flag = 0);
	int get_value(const char *key, int version, char *value, int *valuelen, int *type, double *timestamp, int flag = 0);
	int set_current_version(const char *key, int version);
	int rollback_value(const char *key, int dist = 1);
	int get_num_versions(const char *key, double timestamp);
	int get_timestamps(const char *key, double timestamp, std::list<double>& times);
	int matchkeys(const char *pattern, std::vector<std::string>& keys);
	int copy_key(const char *srckey, const char *destkey, double timestamp);
	int set_latest_timestamp(const char *key, double timestamp);
	int update_value(const char *key, int version, const char *value, int valuelen, int type, double timestamp);
private:
	int get_key_info(const char *key, struct key_info_t *info);
	int set_key_info(const char *key, struct key_info_t *info);
	int get_key_info2(const char *key, struct key_info_t *info);
	int set_key_info2(const char *key, struct key_info_t *info);
	int create_key(const char *key, double timestamp, int flag = 0);
	void lock();
	void unlock();
	int update_version(const char *key, int version, const char *value, int valuelen, int type, double timestamp);
	int make_version_buf(const char *value, int valuelen, int type, double timestamp, char *buf, int buflen);

#ifdef WIN32
	CRITICAL_SECTION sect;
#else
	int mutex;
#endif
	struct handle;
	handle *connection;
	std::map<std::string, key_info_t *> cache;
};
#endif

