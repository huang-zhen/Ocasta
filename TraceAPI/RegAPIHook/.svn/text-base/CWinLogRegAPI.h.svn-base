#ifndef CWINLOGREGAPI_H
#define CWINLOGREGAPI_H

#include <windows.h>
#include "CLogRegAPI.h"
#include "CStaticSharedQueue.h"

// thread-safe CLogReAPI fo Windows
class CWinLogRegAPI : public CLogRegAPI {
public:
	CWinLogRegAPI(int size);
	virtual ~CWinLogRegAPI();
protected:
	int get_entry_num();
	int add_entry(CLogRegAPIEntry *pEntry);
	int remove_entry(CLogRegAPIEntry *pEntry);

	int save_entries();
	int load_entries();
	void reset();
	//
	//int add_tail(CLogRegAPIEntry *pEntry);
	//CLogRegAPIEntry* remove_head();
	void set_key_name(key_t key, std::string& name);
	void reset_key_name(key_t key);
	std::string get_fullname(key_t key, const char* name);

	//mapping of key to name
	std::map<int, std::string> m_key_name_map;
	// lock to protect access to m_key_name_map
	CRITICAL_SECTION m_lock;
	// memory-based shared queue
	CStaticSharedQueue<CLogRegAPIEntry> *m_queue;
};

#endif