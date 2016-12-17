// testtimetravelstore.cpp : Defines the entry point for the console application.
//

#ifdef WIN32
#include "stdafx.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>
#include <iostream>
#include "../timetravelstore/timetravelstore.h"
using namespace std;

// return 1 when key exists
int exists_key(TimeTravelStore &ttstore, const char *key) {
	int ret = 0;
	vector<string> keys;
	if (ttstore.matchkeys("testkey", keys) == 0 && (keys.size() == 1) && (keys[0] == key))
		ret = 1;
	return ret;
}

#if 0
void simpletest()
{
	strcpy(key, "key2");
	store.delete_key(key, 0, 1);
	if (store.create_key(key, 0) != 0) {
		cerr << "Error calling create_key" << endl;
		return 1;
	}
	if (store.get_key_info_ex(key, &key_info) != 0) {
		cerr << "Error calling get_key_info" << endl;
		return 1;
	}
	if (key_info.create_count != 1) {
	      cerr << "Error create_count " << key_info.create_count << " should have been 1" << endl;
	      return 1;
	}
#if 1
	for (int i = 0; i < TEST_SET_COUNT; i++) {
	    sprintf(buf, "data%d", i);
	    if (store.set_value(key, buf, strlen(buf) + 1, TEST_SET_COUNT - i, i * 2) != 0) {
		    cerr << "Error calling set_value" << endl;
		    return 1;
	    }
	}
	if (store.get_key_info_ex(key, &key_info) != 0) {
		cerr << "Error calling get_key_info" << endl;
		return 1;
	}
	if (key_info.set_count != TEST_SET_COUNT) {
		cerr << "Error set_count " << key_info.set_count << " should have been " << TEST_SET_COUNT << endl;
		return 1;
	}
	if (store.get_value(key, -1, buf, NULL, NULL, &time) != 0) {
		    cerr << "Error calling set_value" << endl;
		    return 1;
	}
	cout << "latest: " << buf << " @ " << time << endl;
	for (int i = 0; i < TEST_SET_COUNT; i++) {
		int type;
		int len;
	    if (store.get_value(key, i, buf, &len, &type, &time) != 0) {
		    cerr << "Error calling set_value" << endl;
		    return 1;
	    } else
	      cout << i << ": " << buf << " (len=" << len << ", type=" << type << ") @ " << time << endl;
	}
#endif
	// test binary value
	strcpy(key, "key 2");
	//store.delete_key(key, 0, 1);
	if (store.create_key(key, 0) != 0) {
		cerr << "Error calling create_key" << endl;
		return 1;
	}
	for (int i = 0; i < TEST_SET_COUNT; i++) {
	    if (store.set_value(key, (const char *)&i, sizeof(i), i + 1, i * 3) != 0) {
		    cerr << "Error calling set_value" << endl;
		    return 1;
	    }
	}
	for (int i = 0; i < TEST_SET_COUNT; i++) {
		int type;
		int value;
		int len;
	    if (store.get_value(key, i, (char *)&value, &len, &type, &time) != 0) {
		    cerr << "Error calling set_value" << endl;
		    return 1;
	    } else
	      cout << i << ": " << value << " (len=" << len << ",type=" << type << ") @ " << time << endl;
	}
}
#endif

// all test functions returns 0 when the test is passed

int test_create_key(TimeTravelStore &ttstore, const char *key)
{
		int err = 1;
		TimeTravelStore::key_info_t keyInfo;
		time_t curtime = time(NULL);
		if (exists_key(ttstore, key))
			ttstore.delete_key(key, curtime, 1);

		if (ttstore.create_key(key, curtime, 0) == 0) {
			if (exists_key(ttstore, key) && ttstore.get_key_info_ex(key, &keyInfo) == 0 && keyInfo.create_time == curtime && keyInfo.get_count == 0 && keyInfo.set_count == 0 && keyInfo.set_before_get == 0) {
					err = 0;
			}
		}
		if (err) {
			cerr << "Create key failed" << endl;
		}
		return err;
}

const static int GET_SET_COUNT = 3;

int test_get_set_value(TimeTravelStore &ttstore, const char *key)
{
	int err = 1;
	TimeTravelStore::key_info_t keyInfo;
	char *value = new char[TimeTravelStore::max_value_len];
	if (value == NULL) {
		cerr << "Out of memory in " << __FUNCTION__ << endl;
		goto bail;
	}

	if (ttstore.get_key_info_ex(key, &keyInfo)) {
		cerr << "Get key info failed on " << key << endl;
		goto bail;
	}
	int start_version = keyInfo.set_count;
	
	double timestamps[GET_SET_COUNT];
	double values[GET_SET_COUNT];
	srand(time(NULL));
	for (int i = 0; i < GET_SET_COUNT; i++) {
		bool uniquetime = true;
		double time;
		do {
			time = (double)rand();
			uniquetime = true;
			for (int j = 0; j < i; j++) {
				if (timestamps[j] == time) {
					uniquetime = false;
					break;
				}
			}
		} while (!uniquetime);
		timestamps[i] = time;
		values[i] = (double)rand()/RAND_MAX;
		if (ttstore.set_value(key, (const char *)&values[i], sizeof(values[0]), REG_BINARY, timestamps[i])) {
			cerr << "Set value failed for " << key << endl;
			goto bail;
		}
	}
	if (ttstore.get_key_info_ex(key, &keyInfo)) {
		cerr << "Get key info failed on " << key << endl;
		goto bail;
	}
	// values must be ordered by timestamp
	// number of added values must equal to GET_SET_COUNT
	// each version has correct value and timestamp
	if (keyInfo.set_count != start_version + GET_SET_COUNT) {
		cerr << "Set count is incorrect after set_value" << endl;
		goto bail;;
	}
	for (int version = start_version; version < keyInfo.set_count; version ++) {
		int valuelen, type;
		double timestamp;
		if (ttstore.get_value(key, version, value, &valuelen, &type, &timestamp, 1)) {
			cerr << "Get value failed for " << key << endl;
			goto bail;
		}
		if (valuelen != sizeof(values[0])) {
			cerr << "Set value stores incorrect valuelen" << endl;
			goto bail;
		}
		bool foundtime = false;
		for (int i = 0; i < GET_SET_COUNT; i++) {
			if (timestamp == timestamps[i]) {
				foundtime = true;
				if (memcmp(value, &values[i], valuelen)) {
					cerr << "Set value stores incorrect value" << endl;
					goto bail;
				}
				break;
			}
		}
	}
	err = 0;
bail:
	if (value)
		delete[] value;
	return err;
}

int test_set_latest_timestamp(TimeTravelStore &ttstore, const char *key)
{
	return 0;
}

int main(int argc, char *argv[]) {
	TimeTravelStore ttstore;
	int err = 1;
	const char *server = "127.0.0.1";
	const char *key = "testkey";
	const int db = 63;
	TimeTravelStore::key_info_t keyInfo;

	// not really a loop, just for easy branch
	do {
		if (ttstore.init(server) != 0) {
			cerr << "Initialize TimeTravelStore failed" << endl;
			break;
		}
		if (ttstore.selectdb(db) != 0) {
			cerr << "Select database failed" << endl;
			break;
		}
		if (test_create_key(ttstore, key))
			break;
		if (test_get_set_value(ttstore, key))
			break;
		if (test_set_latest_timestamp(ttstore, key))
			break;
		err = 0;
	} while (0);
	if (ttstore.delete_key(key, 0, 1) == 0)  {
		if (exists_key(ttstore, key)) {
				cerr << "Delete key failed" << endl;
		}
	}
	if (err == 0)
		cout << "Test of timetravelstore passed." << endl;
	return err;
}
