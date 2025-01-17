// keyhandle.cpp
#include <string>
#include "keyhandle.h"
using namespace std;

string KeyHandle::get_predefined_key(const char *key)
{
	string keystr(key);

	if (keystr == "80000000")
		return "CLASSES_ROOT";
	else if (keystr == "80000001")
		return "CURRENT_USER";
	else if (keystr == "80000002")
		return "LOCAL_MACHINE";
	else if (keystr == "80000003")
		return "USERS";
	else if (keystr == "80000004")
		return "PERFORMANCE_DATA";
	else if (keystr == "80000005")
		return "CURRENT_CONFIG";
	else if (keystr == "80000006")
		return "DYN_DATA";
	else if (keystr == "80000050")
		return "PERFORMANCE_TEXT";
	else if (keystr == "80000060")
		return "PERFORMANCE_NLSTEXT";
	else
		return "";
}

string KeyHandle::get_opened_key(const char* pid, const char *key)
{
	string fullkey;
	fullkey = get_predefined_key(key);
	if (fullkey == "") {
		if (key_mappings.find(pid) != key_mappings.end()) {
			if (key_mappings[pid].find(key) != key_mappings[pid].end())
				fullkey = key_mappings[pid][key];
		}
	}
	if (fullkey == "")
		fullkey = "(unknown)";
	return fullkey;
}

void KeyHandle::close_opened_key(const char* pid, const char *key)
{
	if (key_mappings.find(pid) != key_mappings.end()) {
		if (key_mappings[pid].find(key) != key_mappings[pid].end()) {
			key_mappings[pid].erase(key);
		}
	}
}

void KeyHandle::set_opened_key(const char* pid, const char *handle, const string &key)
{
	string keystr(key);
	// remove ending '\'
	if (*(keystr.end() - 1) == '\\')
		keystr.erase(keystr.end() - 1);
	// remove '\\'
	size_t pos = keystr.find("\\\\");
	while (pos != string::npos) {
		keystr.erase(pos, 1);
		pos = keystr.find("\\\\", pos + 1);
	}
	if (key_mappings.find(pid) == key_mappings.end()) {
		map<string, string> temp;
		key_mappings[pid] = temp;
	}
	key_mappings[pid][handle] = keystr;
}

void KeyHandle::close_all_keys(const char *pid)
{
	key_mappings.erase(pid);
}
