#ifndef CLOGREGAPIENTRY_H
#define CLOGREGAPIENTRY_H

#include <string>
#include <vector>
#include <memory.h>
#include <time.h>
#include <iostream>
 
class CLogRegAPIEntry {
public:
	enum EntryType {
		INVALID,
		CREATE_KEY,
		OPEN_KEY,
		CLOSE_KEY,
		REMOVE_KEY,
		GET_VALUE,
		SET_VALUE,
		REMOVE_VALUE
	};
	CLogRegAPIEntry() : m_pid(0), m_type(INVALID)
	{
	}
	CLogRegAPIEntry(unsigned int pid, std::string& name, int datatype, const char *pdata, int size, EntryType type, time_t timestamp, int ret) {
		m_pid = pid;
		m_name = name;
		if (size > 0) {
			for (int i = 0; i < size; i++)
				m_data.push_back(pdata[i]);
		}
		m_type = type;
		m_timestamp = timestamp;
		m_datatype = datatype;
		m_ret = ret;
	}
	~CLogRegAPIEntry() {
	}
	friend std::ostream& operator<<(std::ostream& os, CLogRegAPIEntry& entry) {
		os << entry.m_pid << " " << entry.m_name << " " << entry.m_data.size() << " ";
		for (std::vector<char>::iterator it = entry.m_data.begin(); it != entry.m_data.end(); it++)
			os << (*it);
		os << " " << entry.m_type << " " << entry.m_timestamp << std::endl;
		return os;
	}
	int tobyte(char *buf) {
		char *ptr = buf;
		*(unsigned int*)buf = m_pid;
		buf += sizeof(unsigned int);
		int len = (int)m_name.length();
		*(int*)buf = len;
		buf += sizeof(int);
		memcpy(buf, m_name.c_str(), len);
		buf += len;
		*(int*)buf = m_datatype;
		buf += sizeof(int);
		*(int*)buf = (int)m_data.size();
		buf += sizeof(int);
		for (std::vector<char>::iterator it = m_data.begin(); it != m_data.end(); it++) {
			*buf = (*it);
			buf ++;
		}
		*(int*)buf = m_type;
		buf += sizeof(int);
		*(time_t*)buf = m_timestamp;
		buf += sizeof(time_t);
		*(int*)buf = m_ret;
		buf += sizeof(int);
		return (int)(buf - ptr);
	}
	int frombyte(const char *buf) {
		const char *ptr = buf;
		m_name.clear();
		m_data.clear();
		m_pid = *(unsigned int*)buf;
		buf += sizeof(unsigned int);
		int len = *(int*)buf;
		buf += sizeof(int);
		for (int i = 0; i < len; i++, buf++)
			m_name += *buf;
		m_datatype = *(int*)buf;
		buf += sizeof(int);
		int size = *(int*)buf;
		buf += sizeof(int);
		for (int i = 0; i < size; i++, buf++) {
			m_data.push_back(*buf);
		}
		int temp = *(int*)buf;
		buf += sizeof(int);
		m_type = (EntryType)temp;
		m_timestamp = *(time_t*)buf;
		buf += sizeof(time_t);
		m_ret = *(int*)buf;
		buf += sizeof(int);
		return (int)(buf - ptr);
	}
// public for testing
public:
	unsigned int m_pid;
	std::string m_name;
	std::vector<char> m_data;
	EntryType m_type;
	time_t m_timestamp;
	int m_datatype;
	int m_ret;
};

#endif
