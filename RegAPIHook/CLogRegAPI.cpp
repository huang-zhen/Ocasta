#include <string>
#include <map>
#include <sstream>
#include "CLogRegAPIEntry.h"
#include "CLogRegAPI.h"
using namespace std;

CLogRegAPI::CLogRegAPI(int size)
{
}

CLogRegAPI::~CLogRegAPI()
{
}

// Public Interface
//

void CLogRegAPI::create_key(pid_t pid, key_t key, const char* name, key_t newkey, time_t timestamp, int ret)
{
	set_key_name(newkey, get_fullname(key, name));
	CLogRegAPIEntry *pEntry = new CLogRegAPIEntry(pid, get_fullname(key, name), 0, NULL, 0, CLogRegAPIEntry::CREATE_KEY, timestamp, ret);
	add_entry(pEntry);
	delete pEntry;
}

void CLogRegAPI::open_key(pid_t pid, key_t key, const char* name, key_t newkey, time_t timestamp, int ret)
{
	set_key_name(newkey, get_fullname(key, name));
}

void CLogRegAPI::close_key(pid_t pid, key_t key, time_t timestamp, int ret)
{
	reset_key_name(key);
}

void CLogRegAPI::get_value(pid_t pid, key_t key, const char* subkey, const char* name, int type, const char* pdata, int size, time_t timestamp, int ret)
{
	char buf[256];

	_snprintf(buf, sizeof(buf), "%s\\%s", subkey, name);
	CLogRegAPIEntry *pEntry = new CLogRegAPIEntry(pid, get_fullname(key, buf), type, NULL, 0, CLogRegAPIEntry::GET_VALUE, timestamp, ret);
	add_entry(pEntry);
	delete pEntry;
}

void CLogRegAPI::set_value(pid_t pid, key_t key, const char* subkey, const char* name, int type, const char* pdata, int size, time_t timestamp, int ret)
{
	char buf[256];

	_snprintf(buf, sizeof(buf), "%s\\%s", subkey, name);
	CLogRegAPIEntry *pEntry = new CLogRegAPIEntry(pid, get_fullname(key, buf), type, pdata, size, CLogRegAPIEntry::SET_VALUE, timestamp, ret);
	add_entry(pEntry);
	delete pEntry;
}

void CLogRegAPI::remove_value(pid_t pid, key_t key, const char* name, time_t timestamp, int ret)
{
	CLogRegAPIEntry *pEntry = new CLogRegAPIEntry(pid, get_fullname(key, name), 0, NULL, 0, CLogRegAPIEntry::REMOVE_VALUE, timestamp, ret);
	reset_key_name(key);
	add_entry(pEntry);
	delete pEntry;
}

void CLogRegAPI::remove_key(pid_t pid, key_t key, const char* name, time_t timestamp, int ret)
{
	CLogRegAPIEntry *pEntry = new CLogRegAPIEntry(pid, get_fullname(key, name), 0, NULL, 0, CLogRegAPIEntry::REMOVE_KEY, timestamp, ret);
	reset_key_name(key);
	add_entry(pEntry);
	delete pEntry;
}
