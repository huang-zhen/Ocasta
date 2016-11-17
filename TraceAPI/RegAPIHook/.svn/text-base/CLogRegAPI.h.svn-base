#ifndef CLOGREGAPI_H
#define CLOGREGAPI_H

#include <string>
#include <map>
#include <time.h>
#include "CLogRegAPIEntry.h"

typedef unsigned int pid_t;
typedef unsigned int key_t;

class CLogRegAPI {
public:
	CLogRegAPI(int size);
	virtual ~CLogRegAPI();
	void create_key(pid_t pid, key_t key, const char* name, key_t newkey, time_t timestamp, int ret);
	void open_key(pid_t pid, key_t key, const char* name, key_t newkey, time_t timestamp, int ret);
	void close_key(pid_t pid, key_t key, time_t timestamp, int ret);
	void remove_key(pid_t pid, key_t key, const char* name, time_t timestamp, int ret);
	void get_value(pid_t pid, key_t key, const char* subkey, const char* name, int type, const char* pdata, int size, time_t timestamp, int ret);
	void set_value(pid_t pid, key_t key, const char* subkey, const char* name, int type, const char* pdata, int size, time_t timestamp, int ret);
	void remove_value(pid_t pid, key_t key, const char* name, time_t timestamp, int ret);

protected:
	virtual void reset() = 0;
	virtual int load_entries() = 0;
	virtual int save_entries() = 0;
	virtual int get_entry_num() = 0;
	virtual int remove_entry(CLogRegAPIEntry *) = 0;
	virtual int add_entry(CLogRegAPIEntry *pEntry) = 0;
	virtual void set_key_name(key_t key, std::string& name) = 0;
	virtual void reset_key_name(key_t key) = 0;
	virtual std::string get_fullname(key_t key, const char* name) = 0;
};
#endif
