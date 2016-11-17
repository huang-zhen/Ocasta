#include <string>
#include <map>
#include <sstream>
#include <fstream>
#include <stdio.h>
#include "CLogRegAPIEntry.h"
#include "CWinLogRegAPI.h"
using namespace std;

static const char g_filename[] = "C:\\users\\james\\regapi.dat";
static const wchar_t g_memmapnamep[] = L"CWinLogRegAPIMAP";


CWinLogRegAPI::CWinLogRegAPI(int size) : CLogRegAPI(size)
{
	InitializeCriticalSection(&m_lock);
	//m_queue = new CStaticSharedQueue<CLogRegAPIEntry>("CWinLogRegAPI", size);
}

CWinLogRegAPI::~CWinLogRegAPI()
{
	//delete m_queue;
	DeleteCriticalSection(&m_lock);
}

string CWinLogRegAPI::get_fullname(key_t key, const char* name)
{
	string fullname, name_str;
	if (name)
		name_str = name;
	else
		name_str = "";

	EnterCriticalSection(&m_lock);
	map<int, string>::iterator it = m_key_name_map.find(key);
	if (it != m_key_name_map.end())
		fullname = it->second + "\\" + name_str;
	else {
		ostringstream ostr;

		ostr << key << "\\" << name_str;
		fullname = ostr.str();
	}
	LeaveCriticalSection(&m_lock);
	return fullname;
}

void CWinLogRegAPI::set_key_name(key_t key, string& name)
{
	EnterCriticalSection(&m_lock);
	m_key_name_map[key] = name;
	LeaveCriticalSection(&m_lock);
}

void CWinLogRegAPI::reset_key_name(key_t key)
{
	EnterCriticalSection(&m_lock);
	m_key_name_map.erase(key);
	LeaveCriticalSection(&m_lock);
}

int CWinLogRegAPI::add_entry(CLogRegAPIEntry *pEntry)
{
	//return m_queue->add_tail(pEntry);
	return 0;
}

int CWinLogRegAPI::remove_entry(CLogRegAPIEntry *pEntry)
{
	//return m_queue->remove_head(pEntry);
	return 0;
}

int CWinLogRegAPI::save_entries()
{
	int ret;

	fstream file;
	file.open(g_filename, ios_base::app | ios_base::binary | ios_base::out);
	if (file.is_open()) {
		CLogRegAPIEntry entry;
		int size = m_queue->size();

		for (int i = 0; i < size; i++) {
			char buf[1024];

			if (m_queue->remove_head(&entry) == 1) {
				int len = entry.tobyte(buf);
				file.write((const char *)&len, sizeof(len));
				file.write(buf, len);
			} else
				break;
		}
		file.close();
		ret = 1;
	} else
		ret = 0;
	return ret;
}

int CWinLogRegAPI::load_entries()
{
	int ret;

	ifstream file;
	file.open(g_filename, ios_base::in | ios_base::binary);
	if (file.is_open()) {
		ret = 1;
		while (!file.eof()) {
			CLogRegAPIEntry entry;
			char buf[1024];
			int len;
			file.read((char *)&len, sizeof(len));
			if (!file.good())
				break;
			if (len > sizeof(buf)) {
				ret = -1;
				break;
			}
			file.read(buf, len);
			entry.frombyte(buf);
			m_queue->add_tail(&entry);
		}
		file.close();
	} else
		ret = 0;
	return ret;
}

void CWinLogRegAPI::reset()
{
	m_queue->reset();
}

int CWinLogRegAPI::get_entry_num()
{
	return m_queue->size();
}
