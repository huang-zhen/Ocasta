// testtimetravelstore.cpp
#include <iostream>
#include <vector>
#include <string>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include <conio.h>
#endif
#include "timetravelstore.h"
using namespace std;

const static int GET_SET_COUNT = 20;
const static int TEST_COUNT = 10;

#ifndef WIN32
#define WCHAR wchar_t
#define REG_BINARY TimeTravelStore::REG_BINARY
#define REG_SZ TimeTravelStore::REG_SZ
#endif

// return 1 when key exists
int exists_key(TimeTravelStore &ttstore, const char *key) {
	int ret = 0;
	vector<string> keys;
	if (ttstore.matchkeys("testkey", keys) == 0 && (keys.size() == 1) && (keys[0] == key))
		ret = 1;
	return ret;
}

int test_create_key(TimeTravelStore &ttstore, const char *key)
{
	TimeTravelStore::key_info_t keyInfo;
		int err = 1;
		time_t curtime = time(NULL);
		if (exists_key(ttstore, key))
			ttstore.delete_key(key, 0, 1);

		if (ttstore.create_key_ex(key, (double)curtime, 0) == 0) {
			if (exists_key(ttstore, key) && ttstore.get_key_info_ex(key, &keyInfo) == 0 && keyInfo.create_time == curtime && keyInfo.get_count == 0 && keyInfo.set_count == 0 && keyInfo.set_before_get == 0) {
					err = 0;
			}
		}
		if (err) {
			cerr << "Create key failed" << endl;
		}
		return err;
}

int test_getset_value(TimeTravelStore &ttstore, const char *key)
{
    int err = 1;
	TimeTravelStore::key_info_t keyInfo;
    char *value = NULL;
	int before_version; 
	int before_get_count;
	double values[GET_SET_COUNT];

    value = new char[TimeTravelStore::max_value_len];
    if (value == NULL) {
		cerr << "Out of memory in << " << __FUNCTION__ << endl;
		goto bail;
	}
	if (ttstore.get_key_info_ex(key, &keyInfo)) {
		cerr << "Failed to get key info" << endl;
		goto bail;
	}
	before_version = keyInfo.set_count;
	before_get_count = keyInfo.get_count;
	for (int i = 0; i < GET_SET_COUNT; i++) {
		values[i] = rand() / RAND_MAX;
		if (ttstore.set_value(key, (const char *)&values[i], sizeof(values[0]), REG_BINARY, i + 1)) {
			cerr << "Failed to set value" << endl;
			goto bail;
		}
	}
	if (ttstore.get_key_info_ex(key, &keyInfo)) {
		cerr << "Failed to get key info" << endl;
		goto bail;
	}
	if (keyInfo.set_count != before_version + GET_SET_COUNT) {
		cerr << "Incorrect set_count" << endl;
		goto bail;
	}
	for (int i = 0; i < GET_SET_COUNT; i++) {
		int valuelen = TimeTravelStore::max_value_len, type;
		double timestamp;
		if (ttstore.get_value(key, i, value, &valuelen, &type, &timestamp)) {
			cerr << "Failed to get value" << endl;
			goto bail;
		}
		if (valuelen != sizeof(values[0])) {
			cerr << "Incorrect valuelen for version " << i << endl;
			goto bail;
		}
		if (type != REG_BINARY) {
			cerr << "Incorrect type for version " << i << endl;
			goto bail;
		}
		if (timestamp != i + 1) {
			cerr << "Incorrect timestamp for version " << i << endl;
			goto bail;
		}
		if (memcmp(value, &values[i], valuelen)) {
			cerr << "Incorrect value for version " << i << endl;
			goto bail;
		}
	}
	if (ttstore.get_key_info_ex(key, &keyInfo)) {
		cerr << "Failed to get key info" << endl;
		goto bail;
	}
	if (keyInfo.get_count != before_get_count + GET_SET_COUNT) {
		cerr << "Incorrect get_count" << endl;
		goto bail;
	}
	err = 0;
bail:
	if (value)
		delete[] value;
    return err;
}

int test_copy_key(TimeTravelStore &ttstore, const char *key, const char *newkey)
{
	TimeTravelStore::key_info_t keyInfo, newkeyInfo;
	int err = 1;
	char *value = NULL, *newvalue = NULL;

	value = new char[TimeTravelStore::max_value_len];
	if (value == NULL) {
		cerr << "Out of memory in " << __FUNCTION__ << endl;
		goto bail;
	}
	newvalue = new char[TimeTravelStore::max_value_len];
	if (newvalue == NULL) {
		cerr << "Out of memory in " << __FUNCTION__ << endl;
		goto bail;
	}

	if (ttstore.get_key_info_ex(key, &keyInfo)) {
		cerr << "get key info on " << key << " failed" << endl;
		goto bail;
	}
	if (ttstore.copy_key(key, newkey, 0)) {
		cerr << "Copy key failed" << endl;
		goto bail;
	}
	if (ttstore.get_key_info_ex(newkey, &newkeyInfo)) {
		cerr << "get key info on " << newkey << " failed" << endl;
		goto bail;
	}
	if (memcmp(&keyInfo, &newkeyInfo, sizeof(TimeTravelStore::key_info_t))) {
		cerr << "Copy key failed to create identical key info" << endl;
		goto bail;
	}
	for (int i = 0; i < keyInfo.set_count; i++) {
		int valuelen = TimeTravelStore::max_value_len, newvaluelen = TimeTravelStore::max_value_len;
		double timestamp, newtimestamp;
		int type, newtype;
		if (ttstore.get_value(key, i, value, &valuelen, &type, &timestamp, 1)) {
			cerr << "Get value failed on " << key << endl;
			goto bail;
		}
		if (ttstore.get_value(newkey, i, newvalue, &newvaluelen, &newtype, &newtimestamp, 1)) {
			cerr << "Get value failed on " << newkey << endl;
			goto bail;
		}
		if (type != newtype || valuelen != newvaluelen || timestamp != newtimestamp || memcmp(value, newvalue, valuelen)) {
			cerr << "Copy key failed to create identical value for version " << i << endl;
			goto bail;
		}
	}
	err = 0;
bail:
	if (ttstore.delete_key(newkey, 0, 1))
		cerr << "Failed to delete " << newkey << endl;

	if (value)
		delete[] value;
	if (newvalue)
		delete[] newvalue;
	return err;
}

int check_key_integrity(TimeTravelStore &ttstore, const char *key, double timestamps[], double set_timestamp)
{
	double latest_timestamp = 0;
	int err = 1;
	TimeTravelStore::key_info_t keyInfo;

	if (ttstore.get_key_info_ex(key, &keyInfo)) {
		cerr << "Failed to get key info" << endl;
		goto bail;
	}

	for (int i = 0; i < keyInfo.set_count; i++) {
		double timestamp;
		if (ttstore.get_value(key, i, NULL, NULL, NULL, &timestamp, 1)) {
			cerr << "Failed on get value of version " << i << endl;
			goto bail;
		}
		if (timestamp > latest_timestamp)
			latest_timestamp = timestamp;
		else if (timestamp < latest_timestamp) {
			cerr << "Incorrectly changed timestamp for version " << i << endl;
			goto bail;
		}
		if (timestamp != timestamps[i] && timestamp != set_timestamp) {
			cerr << "Incorrectly changed timestamp for version " << i << endl;
			goto bail;
		}
	}
	err = 0;
bail:
	return err;
}

int test_set_latest_timestamp(TimeTravelStore &ttstore, const char *key)
{
	TimeTravelStore::key_info_t keyInfo;
	double *timestamps = NULL;	
	int err = 1;
	double latest_timestamp = 0;

	if (ttstore.get_key_info_ex(key, &keyInfo)) {
		cerr << "Failed on get key info" << endl;
		goto bail;
	}
	timestamps = new double[keyInfo.set_count];
	if (timestamps == NULL) {
		cerr << "Out of memory in " << __FUNCTION__ << endl;
		goto bail;
	}
	for (int i = 0; i < keyInfo.set_count; i++) {
		if (ttstore.get_value(key, i, NULL, NULL, NULL, &timestamps[i], 1)) {
			cerr << "Failed on get value of version " << i << endl;
			goto bail;
		}
	}
	// set latest timestamp to be the latest of timestamps -- no change to the key should be made
	if (ttstore.set_latest_timestamp(key, timestamps[keyInfo.set_count - 1])) {
		cerr << "Failed on set latest timestamp" << endl;
		goto bail;
	}
	err = check_key_integrity(ttstore, key, timestamps, timestamps[keyInfo.set_count - 1]);
	if (err)
		goto bail;
	// set latest timestamp to be greater than any of timestamps
	if (ttstore.set_latest_timestamp(key, timestamps[keyInfo.set_count - 1] + 1)) {
		cerr << "Failed on set latest timestamp" << endl;
		goto bail;
	}
	err = check_key_integrity(ttstore, key, timestamps, timestamps[keyInfo.set_count - 1] + 1);
	if (err)
		goto bail;
	// set latest timestamp to be lower than any of timestamps
	if (ttstore.set_latest_timestamp(key, timestamps[0] - 1)) {
		cerr << "Failed on set latest timestamp" << endl;
		goto bail;
	}
	err = check_key_integrity(ttstore, key, timestamps, timestamps[0] - 1);
	if (err)
		goto bail;
bail:
	if (timestamps)
		delete[] timestamps;
	return err;
}

// copy original key to a backup
// update a random version
// compare updated key with the backup
int test_update_value(TimeTravelStore &ttstore, const char *key)
{
	TimeTravelStore::key_info_t keyInfo, newkeyInfo;
	int err = 1;
	char *value = NULL, *newvalue = NULL, *updatedValue = NULL;
	char *newkey = NULL;
	int updatedVersion, updatedValueLen;

	value = new char[TimeTravelStore::max_value_len];
	if (value == NULL) {
		cerr << "Out of memory in " << __FUNCTION__ << endl;
		goto bail;
	}
	newvalue = new char[TimeTravelStore::max_value_len];
	if (newvalue == NULL) {
		cerr << "Out of memory in " << __FUNCTION__ << endl;
		goto bail;
	}
	updatedValue = new char[TimeTravelStore::max_value_len];
	if (updatedValue == NULL) {
		cerr << "Out of memory in " << __FUNCTION__ << endl;
		goto bail;
	}
	newkey = new char[TimeTravelStore::max_key_len];
	if (newkey == NULL) {
		cerr << "Out of memory in " << __FUNCTION__ << endl;
		goto bail;
	}
	sprintf(newkey, "%s.copy", key);
	if (ttstore.copy_key(key, newkey, 0)) {
		cerr << "copy key failed" << endl;
		goto bail;
	}
	if (ttstore.get_key_info_ex(key, &keyInfo)) {
		cerr << "get key info on " << key << " failed" << endl;
		goto bail;
	}
	if (ttstore.get_key_info_ex(newkey, &newkeyInfo)) {
		cerr << "get key info on " << key << " failed" << endl;
		goto bail;
	}
	updatedVersion = (double) rand() / RAND_MAX * keyInfo.set_count;
	updatedValueLen = TimeTravelStore::max_value_len;
	int type;
	double timestamp;
	if (ttstore.get_value(newkey, updatedVersion, updatedValue, &updatedValueLen, &type, &timestamp, 1)) {
		cerr << "Failed to get value for version " << updatedVersion << " of " << key << endl;
		goto bail;
	}
	updatedValueLen = (double) rand() / RAND_MAX * TimeTravelStore::max_value_len;
	for (int i = 0; i < updatedValueLen; i++)
		updatedValue[i] = rand() / RAND_MAX * 256;
	if (ttstore.update_value(newkey, updatedVersion, updatedValue, updatedValueLen, type, timestamp)) {
		cerr << "Failed to update value for version " << updatedVersion << " of " << key << endl;
		goto bail;
	}
	if (memcmp(&keyInfo, &newkeyInfo, sizeof(TimeTravelStore::key_info_t))) {
		cerr << "Copy key failed to create identical key info" << endl;
		goto bail;
	}
	for (int i = 0; i < keyInfo.set_count; i++) {
		int valuelen = TimeTravelStore::max_value_len, newvaluelen = TimeTravelStore::max_value_len;
		double timestamp, newtimestamp;
		int type, newtype;
		if (ttstore.get_value(key, i, value, &valuelen, &type, &timestamp, 1)) {
			cerr << "Get value failed on " << key << endl;
			goto bail;
		}
		if (ttstore.get_value(newkey, i, newvalue, &newvaluelen, &newtype, &newtimestamp, 1)) {
			cerr << "Get value failed on " << newkey << endl;
			goto bail;
		} 
		if (type != newtype || timestamp != newtimestamp) {
			cerr << "Incorrectly value for version " << i << endl;
			goto bail;
		}
		if (i == updatedVersion) {
			if (newvaluelen != updatedValueLen || memcmp(newvalue, updatedValue, newvaluelen)) {
				cerr << "Incorrectly value for version " << i << endl;
				goto bail;
			}
		} else {
			if (newvaluelen != valuelen || memcmp(newvalue, value, newvaluelen)) {
				cerr << "Incorrectly value for version " << i << endl;
				goto bail;
			}
		}
	}
	err = 0;
bail:
	if (ttstore.delete_key(newkey, 0, 1))
		cerr << "Failed to delete " << newkey << endl;

	if (value)
		delete[] value;
	if (newvalue)
		delete[] newvalue;
	if (updatedValue)
		delete[] updatedValue;
	if (newkey)
		delete[] newkey;
	return err;
}

// performance tests
int test_set_key_info(int count)
{
	TimeTravelStore ttstore;
	time_t starttime = time(NULL);
	TimeTravelStore::key_info_t keyInfo;
	memset(&keyInfo, 0, sizeof(keyInfo));

	if (ttstore.init("127.0.0.1")) {
		cerr << "Initialize TimeTravelStore failed!" << endl;
		goto bail;
	}
	if (ttstore.delete_key("CURRENT_USER\\Software\\Sunbird\\TraceAPI\\TestValue", 0, 1)) {
		cerr << "Delete key failed" << endl;
		goto bail;
	}
	if (ttstore.create_key_ex("CURRENT_USER\\Software\\Sunbird\\TraceAPI\\TestValue", 0)) {
		cerr << "Create key failed" << endl;
		goto bail;
	}
	for (int i = 0; i < count; i++) {
		if (ttstore.set_key_info_ex("CURRENT_USER\\Software\\Sunbird\\TraceAPI\\TestValue", &keyInfo)) {
			cerr << "Failed on set key info" << endl;
			goto bail;
		}
	}
bail:		
	time_t endtime = time(NULL);
	int elapsedtime = (int)endtime - starttime;
	cout << "Run set_key_info " << count << " times took " << elapsedtime << " seconds" << endl;
	return elapsedtime;
}

int test_get_key_info(int count)
{
	TimeTravelStore ttstore;
	time_t starttime = time(NULL);
	TimeTravelStore::key_info_t keyInfo;
	if (ttstore.init("127.0.0.1")) {
		cerr << "Initialize TimeTravelStore failed!" << endl;
		goto bail;
	}
	for (int i = 0; i < count; i++) {
		if (ttstore.get_key_info_ex("CURRENT_USER\\Software\\Sunbird\\TraceAPI\\TestValue", &keyInfo)) {
			cerr << "Failed on get key info" << endl;
			goto bail;
		}
	}
bail:		
	time_t endtime = time(NULL);
	int elapsedtime = (int)endtime - starttime;
	cout << "Run get_key_info " << count << " times took " << elapsedtime << " seconds" << endl;
	return elapsedtime;
}

// return elapsed time in seconds
static const char* key = "CURRENT_USER\\Software\\Sunbird\\TraceAPI\\TestValue";
int test_update_value(int count)
{
	int size = 128;
	TimeTravelStore ttstore;
	time_t starttime;
	int retCode;
	WCHAR *data = new WCHAR[size];
	if (data == NULL) {
		cerr << "Out of memory!" << endl;
		goto bail;
	}
	if (ttstore.init("127.0.0.1")) {
		cerr << "Initialize TimeTravelStore failed!" << endl;
		goto bail;
	}
	retCode = ttstore.delete_key(key, 0, 1);
	if (retCode != 0) {
		cerr << "delete_key failed!" << endl;
		goto bail;
	}
	retCode = ttstore.create_key_ex(key, 0);
	if (retCode != 0) {
		cerr << "create_key failed!" << endl;
		goto bail;
	}
	retCode = ttstore.set_value(key, (const char*)data, size * sizeof(WCHAR), REG_SZ, 0); 
	if (retCode != 0) {
		cerr << "set_value failed!" << endl;
		goto bail;
	}
	starttime = time(NULL);
	for (int i = 0; i < size - 1; i++) {
		int value = (double)rand() / RAND_MAX * 26 + 65;
		data[i] = value;
	}
	data[size - 1] = 0;
	for (int i = 0; i < count; i++) {
		int retCode = ttstore.update_value(key, 0, (const char*)data, size * sizeof(WCHAR), REG_SZ, 0); 
		if (retCode != 0) {
			cerr << "set_value failed!" << endl;
			goto bail;
		}
	}
bail:
	if (data)
		delete[] data;
	time_t endtime = time(NULL);
	int elapsedtime = (int)endtime - starttime;
	cout << "Run update_value " << count << " times took " << elapsedtime << " seconds" << endl;
	return elapsedtime;
}

int test_set_value(int count)
{
	int size = 128;
	TimeTravelStore ttstore;
	time_t starttime;
	int retCode;
	WCHAR *data = new WCHAR[size];
	if (data == NULL) {
		cerr << "Out of memory!" << endl;
		goto bail;
	}
	if (ttstore.init("127.0.0.1")) {
		cerr << "Initialize TimeTravelStore failed!" << endl;
		goto bail;
	}
	retCode = ttstore.delete_key(key, 0, 1);
	if (retCode != 0) {
		cerr << "delete_key failed!" << endl;
		goto bail;
	}
	retCode = ttstore.create_key_ex(key, 0);
	if (retCode != 0) {
		cerr << "create_key failed!" << endl;
		goto bail;
	}
	retCode = ttstore.set_value(key, (const char*)data, size * sizeof(WCHAR), REG_SZ, 0); 
	if (retCode != 0) {
		cerr << "set_value failed!" << endl;
		goto bail;
	}
	for (int i = 0; i < size - 1; i++) {
		int value = (double)rand() / RAND_MAX * 26 + 65;
		data[i] = value;
	}
	data[size - 1] = 0;
	starttime = time(NULL);
	for (int i = 0; i < count; i++) {
		int retCode = ttstore.set_value(key, (const char*)data, size * sizeof(WCHAR), REG_SZ, 0); 
		if (retCode != 0) {
			cerr << "set_value failed!" << endl;
			goto bail;
		}
	}
bail:
	time_t endtime = time(NULL);
	if (data)
		delete[] data;
	int elapsedtime = (int)endtime - starttime;
	cout << "Run set_value " << count << " times took " << elapsedtime << " seconds" << endl;
	return elapsedtime;
}

int test_get_value(int count)
{
	int size = 128;
	TimeTravelStore ttstore;
	time_t starttime;
	int retCode;
	WCHAR *data = new WCHAR[size];
	if (data == NULL) {
		cerr << "Out of memory!" << endl;
		goto bail;
	}
	if (ttstore.init("127.0.0.1")) {
		cerr << "Initialize TimeTravelStore failed!" << endl;
		goto bail;
	}
	retCode = ttstore.delete_key(key, 0, 1);
	if (retCode != 0) {
		cerr << "delete_key failed!" << endl;
		goto bail;
	}
	retCode = ttstore.create_key_ex(key, 0);
	if (retCode != 0) {
		cerr << "create_key failed!" << endl;
		goto bail;
	}
	retCode = ttstore.set_value(key, (const char*)data, size * sizeof(WCHAR), REG_SZ, 0); 
	if (retCode != 0) {
		cerr << "set_value failed!" << endl;
		goto bail;
	}
	starttime = time(NULL);
	for (int i = 0; i < count; i++) {
		int dataSize = size * sizeof(WCHAR);
		int type;
		double timeStamp;
		int retCode = ttstore.get_value(key, -1, (char*)data, &dataSize, &type, &timeStamp); 
		if (retCode != 0) {
			cerr << "get_value failed!" << endl;
			goto bail;
		}
	}
bail:
	time_t endtime = time(NULL);
	if (data)
		delete[] data;
	int elapsedtime = (int)endtime - starttime;
	cout << "Run get_value " << count << " times took " << elapsedtime << " seconds" << endl;
	return elapsedtime;
}

static const int TEST_PERF_COUNT = 100000;

int main(int argc, char *argv[]) {
	TimeTravelStore ttstore;
	int err = 1;
	const char *server = "127.0.0.1";
	const char *key = "testkey";
	const char *newkey = "testkey.copy";
	const int db = 63;
	//TimeTravelStore::key_info_t keyInfo;

	srand((int)time(NULL));

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
			goto bail;

		if (test_getset_value(ttstore, key))
			goto bail;

		if (test_copy_key(ttstore, key, newkey))
			break;

		if (test_set_latest_timestamp(ttstore, key))
			break;

		for (int i = 0; i < TEST_COUNT; i++) {
			if (test_update_value(ttstore, key))
				goto bail;
		}

		test_set_key_info(TEST_PERF_COUNT);
		
		test_get_key_info(TEST_PERF_COUNT);

		test_update_value(TEST_PERF_COUNT);

		test_set_value(TEST_PERF_COUNT);

		test_get_value(TEST_PERF_COUNT);

		err = 0;
	} while (0);
bail:
	if (ttstore.delete_key(key, 0, 1) != 0 || exists_key(ttstore, key)) {
		cerr << "Delete " << key << " failed" << endl;
	}
	if (ttstore.delete_key(newkey, 0, 1) != 0 || exists_key(ttstore, newkey)) {
		cerr << "Delete " << newkey << " failed" << endl;
	}
	if (!err)
		cout << "Test of TimeTravelStore passed" << endl;
	else
		cout << "Test of TimeTravelStore failed" << endl;
	cout << "Press any key...";
	getchar();
	return err;
}
