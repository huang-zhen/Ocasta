// keyhandle.h
#ifndef KEYHANLDE_H
#define KEYHANDLE_H

#include <string>
#include <map>

class KeyHandle {
public:
	std::string get_opened_key(const char* pid, const char *key);
	void close_opened_key(const char* pid, const char *key);
	void set_opened_key(const char* pid, const char *handle, const std::string &key);
	void close_all_keys(const char *pid);
private:
	std::string get_predefined_key(const char *key);
	std::map<std::string, std::string> key_mappings;
};
#endif
