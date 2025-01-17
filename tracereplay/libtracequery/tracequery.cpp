// tracequery.cpp
//
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <strstream>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <string.h>
#include <list>
#include <limits>
#include <sstream>
#include "tracequery.h"
#include "../tracequery/clusterkeys.h"
#ifdef WIN32
#include "..\libregtool\libregtool.h"
#endif
using namespace std;

#ifndef WIN32
#define REG_SZ TimeTravelStore::REG_SZ
#define REG_EXPAND_SZ TimeTravelStore::REG_EXPAND_SZ
#define REG_DWORD TimeTravelStore::REG_DWORD
#define REG_BINARY TimeTravelStore::REG_BINARY
#endif

//#define DEBUG

TraceQuery::TraceQuery()
{
	ttstore = new TimeTravelStore();
	appstore = new AppStateStore();
	m_interactive = true;
	m_threshold = 0.0;
	m_clustering = 0;
	m_windowsize = 1;
	traverse_policy = BREADTH_FIRST;
	rollback_strategy = ROLLBACK_NONE;
	m_time_bound = 0;
	m_clusteringmode = 0;
}

TraceQuery::~TraceQuery()
{
	delete appstore;
	delete ttstore;
}

int TraceQuery::init(const char *server)
{
	if (!ttstore) {
		cerr << "Error creating TimeTravelStore" << endl;
		return 1;
	}
	if (ttstore->init(server)) {
		cerr << "Error initializing TimeTravelStore" << endl;
		return 1;
	}
	if (!appstore) {
		cerr << "Error creating AppStateStore" << endl;
		return 1;
	}
	if (appstore->init(server)) {
		cerr << "Error initializing AppStateStore" << endl;
		return 1;
	}
	return 0;
}

void TraceQuery::settrace(const char *tracename)
{
	strcpy(this->tracename, tracename);
	appstore->settrace(tracename);
	int id = appstore->getid(tracename);
	if (id > 0) {
		ttstore->selectdb(id * 2 - 1);
		appstore->selectdb(id * 2);
	}
}

void TraceQuery::listtraces(vector<string>& traces)
{
	appstore->gettraces(traces);
}

string TraceQuery::value2str(int type, char *value)
{
	char *buf = new char[TimeTravelStore::max_value_len];
	if (buf == NULL)
		return "";
	strstream ss;
	switch (type) {
		case REG_SZ:
		case REG_EXPAND_SZ:
			sprintf(buf, "%S", (wchar_t *)value);
			ss << type << ": " << buf << ends;
			break;
		case REG_DWORD:
			ss << type << ": " << *(int *)value << ends;
			break;
		case REG_BINARY:
			ss << type << ": BINARY" << ends;
			break;
		case -1:
			ss << type << ": DELETED" << ends;
			break;
		default:
			ss << type << ": UNKNOWN TYPE" << ends;
			break;
	}
	delete[] buf;
	return ss.str();
}

string TraceQuery::time2str(int time)
{
	time_t t = (time_t)time;
	struct tm *tm = localtime(&t);
	strstream ss;
	ss << tm->tm_year + 1900 << "-" << tm->tm_mon + 1 << "-" << tm->tm_mday << " " << tm->tm_hour << ":" << tm->tm_min << ":" << tm->tm_sec << ends;
	return ss.str();
}

int TraceQuery::getlatestversion(const char *key, string &value)
{
	int ret = -1;
	int valuelen = TimeTravelStore::max_value_len;
	int type;
	double timestamp;
	char *buf = new char[TimeTravelStore::max_value_len];
	if (buf == NULL)
		goto bail;

	if (ttstore->get_value(key, -1, buf, &valuelen, &type, &timestamp, 1)==0) {
		assert(valuelen < sizeof(buf));
		value = value2str(type, buf);
		ret = 0;
	}
bail:
	if (buf)
		delete[] buf;
	return -1;
}

double TraceQuery::getratio(const char *key, int &num_versions)
{
	TimeTravelStore::key_info_t keyinfo;
	if (ttstore->get_key_info_ex(key, &keyinfo)) {
		cerr << __FUNCTION__ << ": failed to get key info for " << key << endl;
		return -1;
	}
	double ratio = MAX_RATIO;
	num_versions = ttstore->get_num_versions(key, 0);
	if (num_versions == 0)
		num_versions = 1;
	if (keyinfo.get_count > 0)
		ratio = (double)num_versions/keyinfo.get_count;
	else
		ratio = MAX_RATIO;
	return ratio;
}

void TraceQuery::calcintervaldist(TimeTravelStore::key_info_t &key_info, const char *key, double& avg, double& var, int& outliers, double& cv)
{
	vector<int> intervals;
	int lasttime = 0;
	int num = key_info.set_count;
#if 0
	// change to use gettimestamps for performance
	list<double> times;
	if (ttstore->get_timestamps(key, 0, times) > 0) {
		for (int version = 0; version < num; version ++) {
		}
	}
#else
	if (num > 1000)
		num = 1000;
	for (int version = 0; version < num; version++) {
		int type;
		double timestamp;
		//char buf[1024];

		if (ttstore->get_value(key, version, NULL, NULL, &type, &timestamp, 1)==0) {
			int time = (int)timestamp;
			if (lasttime)
				intervals.push_back(time - lasttime);
			lasttime = time;
		} else
			cerr << "Failed to get value@" << version << " for " << key << endl;
	}
#endif
	int sum = 0;	
	for (vector<int>::iterator it = intervals.begin(); it != intervals.end(); it++) {
		sum += *it;
	}
	if (sum > 0) {
		avg = sum / intervals.size();
		double diffsum = 0;
		for (vector<int>::iterator it = intervals.begin(); it != intervals.end(); it++) {
			double diff = *it - avg;
			diffsum += diff * diff;
		}
		var = sqrt((double)diffsum / intervals.size());
		cv = var/avg;
		int outliers = 0;
		for (vector<int>::iterator it = intervals.begin(); it != intervals.end(); it++) {
			if (fabs(*it - avg) > var)
				outliers ++;
		}
	}
}

void TraceQuery::listkeys(string appname, string name, vector<string> &keys)
{
	string filename(tracename);
	filename += ".";
	filename += appname;
	filename += ".";
	filename += name;
	filename += ".csv";

	int totalset = 0;
	int totallabeledset = 0;
	
	removeconstkeys(keys);
	ofstream ofs(filename.c_str());
	cout << "\t" << name << ":" << endl;
	for (int i = 0; i < keys.size(); i++) {
			TimeTravelStore::key_info_t key_info;
			if (!ttstore->get_key_info_ex(keys[i].c_str(), &key_info)) {
				int num_versions;
				double ratio = getratio(keys[i].c_str(), num_versions);
				if (key_info.set_before_get & 0x80)
					totallabeledset += key_info.set_count;
				totalset += key_info.set_count;
				double avg = 0, var = 0, cv = 0;
				int outliers = 0;
				//calcintervaldist(key_info, keys[i].c_str(), avg, var, outliers, cv);
				//string latestversion;
				//getlatestversion(ttstore, keys[i].c_str(), latestversion);
				cout << i + 1 << ", \"" << keys[i].c_str() << "\", " << key_info.get_count << ", " << key_info.set_count << ", " << (key_info.set_before_get & 0x7f) << ", " << ((key_info.set_before_get & 0x80) >> 7) << ", " << ratio << num_versions << endl;
				if (ofs.good()) {
					char sdata[1024];
#ifdef WIN32
					unsigned char data[1024];
					DWORD type, ndata = sizeof(data);
					
					int ret = getkeyvalue(keys[i].c_str(), data, &type, &ndata, sdata);
					if (ret != 0)
						strcpy(sdata, "INVALID");
#else
					strcpy(sdata, "INVALID");
#endif
					ofs << i + 1 << ",\"" << keys[i].c_str() << "\"," << sdata << "," << key_info.get_count << "," << key_info.set_count << "," << (key_info.set_before_get & 0x7f) << "," << ((key_info.set_before_get & 0x80) >> 7) << "," << ratio << "," << num_versions << "," << avg << "," << var << "," << cv << "," << outliers << endl;
				}
			} else {
				if (ttstore->create_key(keys[i].c_str(), 0, 1))
					cout << "Failed creating " << keys[i].c_str() << endl;
				cout << i + 1 << ", \"" << keys[i].c_str() << "\", 0, 0, 0, 0, 0.0" << endl;
				if (ofs.good())
					ofs << i + 1 << ", \"" << keys[i].c_str() << "\", 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0" << endl;
			}
	}
	//if (totalset > 0)
	//	ofs << "Total Updates, " << totalset << ", " << totallabeledset << ", " << (double)(totalset - totallabeledset)/totalset << endl;
	ofs.close();
}

void TraceQuery::listkeyvalue(const char *key)
{
	TimeTravelStore::key_info_t key_info;
	if (ttstore->get_key_info_ex(key, &key_info) != -1) {
		cout << key << ", " << key_info.get_count << ", " << ttstore->get_num_versions(key, 0) << "(" << key_info.set_count << ")" << ", " << (key_info.set_before_get & 0x7f) << ", " << ((key_info.set_before_get & 0x80) >> 7) << endl; 
		char *value = new char[TimeTravelStore::max_value_len];
		char *buf = new char[TimeTravelStore::max_value_len];
		for (int version = key_info.set_count - 1; version >= 0; version--) {
			int valuelen = TimeTravelStore::max_value_len;
			int type;
			double timestamp;
			if (ttstore->get_value(key, version, value, &valuelen, &type, &timestamp, 1)==0) {
				time_t time = (time_t)timestamp;
				struct tm *tm = localtime(&time);
				strstream ss;
				ss << tm->tm_year + 1900 << "-" << tm->tm_mon + 1 << "-" << tm->tm_mday << " " << tm->tm_hour << ":" << tm->tm_min << ":" << tm->tm_sec << ends;
				switch (type) {
					case REG_SZ:
					case REG_EXPAND_SZ:
						sprintf(buf, "%S", (wchar_t *)value);
						if (buf[0] == '\0')
							sprintf(buf, "%s", value);
						cout << "\t" << ss.str() << "\t" << type << ": " << buf << endl;
						break;
					case REG_DWORD:
						//cout << "\t" << ss.str() << "\t" << type << ": " << *(int *)value << endl;
#pragma message("**** Note: REG_DWORD was stored as string -- need to fix replay ****")
						cout << "\t" << ss.str() << "\t" << type << ": " << value << endl;
						break;
					case REG_BINARY:
						cout << "\t" << ss.str() << "\t" << type << ": BINARY" << endl;
						break;
					case -1:
						cout << "\t" << ss.str() << "\tDELETED" << endl;
						break;
					default:
						cout << "\t" << ss.str() << "\t" << type << ": UNKNWON TYPE" << endl;
						break;
				}
			}
		}
		delete[] value;
		delete[] buf;
	} else
		cout << "Error calling get_key_info_ex for " << key << endl;
}

void TraceQuery::listkeyvalues(const char *appname, const char *name, vector<string> &keys)
{
	removeconstkeys(keys);
	do {
		cout << "List values for " << name << " key (0 for exit, -1 for list, -2 for search): ";
		char buf[80];
		cin >> buf;
		int choice = atoi(buf);
		if (choice == 0)
			break;
		else if (choice == -1) {
			listkeys(appname, name, keys);
		} else if (choice == -2) {
			cout << "Enter key pattern: ";
			cin >> buf;
			for (int i = 0; i < keys.size(); i++) {
				if (keys[i].find(buf) != string::npos)
					cout << i + 1 << ": " << keys[i].c_str() << endl;
			}
		} else if (choice >= 1 && choice <= keys.size()) {
			choice --;

			listkeyvalue(keys[choice].c_str());
		} else
			cout << "Invalid choice, try again" << endl;
	} while (1);
}

int TraceQuery::getappstat(const char *appname, int *numberaccess, int *numberupdate, int *numberdelete, double *starttime, double *endtime, set<string>& uniquekeys)
{
	vector<string> pids;

	appstore->getproc(appname, pids);

	*numberupdate = *numberdelete = *numberaccess = 0;
	*starttime = (double)time(NULL);
	*endtime = 0;
	for (vector<string>::iterator it = pids.begin(); it != pids.end(); it++) {
		vector<string> akeys, ukeys, dkeys;

		*numberaccess += appstore->getnumberaccess(appname, it->c_str());
		appstore->getaccessedkeys(appname, it->c_str(), akeys);
		
		*numberupdate += appstore->getnumberupdate(appname, it->c_str());
		appstore->getupdatedkeys(appname, it->c_str(), ukeys);

		*numberdelete += appstore->getnumberdelete(appname, it->c_str());
		appstore->getdeletedkeys(appname, it->c_str(), dkeys);

		for (vector<string>::iterator kit = akeys.begin(); kit != akeys.end(); kit++)
			uniquekeys.insert(*kit);

		for (vector<string>::iterator kit = ukeys.begin(); kit != ukeys.end(); kit++)
			uniquekeys.insert(*kit);

		for (vector<string>::iterator kit = dkeys.begin(); kit != dkeys.end(); kit++)
			uniquekeys.insert(*kit);

		double pidstarttime = appstore->getstarttime(appname, it->c_str());
		double pidendtime = appstore->getendtime(appname, it->c_str());
		if (pidstarttime < *starttime)
			*starttime = pidstarttime;
		if (pidendtime > *endtime)
			*endtime = pidendtime;
	}
	return 0;
}

int TraceQuery::aggregateaccess(const char *appname, set<string> &accessedkeys, set<string> &updatedkeys, set<string> &deletedkeys)
{
	int totalonly = 1;

	vector<string> pids;
	appstore->getproc(appname, pids);

	for (vector<string>::iterator it = pids.begin(); it != pids.end(); it++) {
		if (!totalonly)
			cerr << "pid: " << it->c_str() << endl;
		double executiontime = appstore->getexecutiontime(appname, it->c_str())/60.0;
		totalexecutiontime += executiontime;
		if (!totalonly)
			cerr << "\texecution time: " << executiontime << " minutes" << endl;
		int numberaccess = appstore->getnumberaccess(appname, it->c_str());
		if (numberaccess < 0)
			numberaccess = 0;
		else
			totalaccess += numberaccess;
		if (!totalonly)
			cerr << "\tkey accesses: " << numberaccess << endl;
		vector<string> keys;
		keys.clear();
		int numaccessedkeys = appstore->getaccessedkeys(appname, it->c_str(), keys);
		if (!totalonly)
			cerr << "\taccessed keys: " << numaccessedkeys << endl;
		//cout << "List the keys? (y/n) ";
		//char input[80];
		//cin >> input;
		//if (input[0] == 'y' || input[0] == 'Y') {
		for (vector<string>::iterator kit = keys.begin(); kit != keys.end(); kit++) {
			if (!totalonly) {
				cerr << "\tAccess " << kit->c_str() << endl;
			}
			accessedkeys.insert(*kit);
		}
		//}
		keys.clear();
		int numberupdate = appstore->getnumberupdate(appname, it->c_str());
		if (numberupdate < 0)
			numberupdate = 0;
		else
			totalupdate += numberupdate;
		if (!totalonly)
			cerr << "\tkey updates: " << numberupdate << endl;
		int numupdatedkeys = appstore->getupdatedkeys(appname, it->c_str(), keys);
		if (!totalonly)
			cerr << "\tupdated keys: " << numupdatedkeys << endl;
		for (vector<string>::iterator kit = keys.begin(); kit != keys.end(); kit++) {
			if (!totalonly)
				cerr << "\tUpdate " << kit->c_str() << endl;
			updatedkeys.insert(*kit);
		}
		keys.clear();
		int numberdelete = appstore->getnumberdelete(appname, it->c_str());
		if (numberdelete < 0)
			numberdelete = 0;
		else
			totaldelete += numberdelete;
		if (!totalonly)
			cerr << "\tkey deletes: " << numberdelete << endl;
		int numdeletedkeys = appstore->getdeletedkeys(appname, it->c_str(), keys);
		if (!totalonly)
			cerr << "\tdeleted keys: " << numdeletedkeys << endl;
		for (vector<string>::iterator kit = keys.begin(); kit != keys.end(); kit++) {
			if (!totalonly)
				cerr << "\tDelete " << kit->c_str() << endl;
			deletedkeys.insert(*kit);
		}
	}
	return pids.size();
}

double ** TraceQuery::calckeydist(const char *appname, vector<string>& keys, int output)
{
	double **distmatrix = NULL;

	//set<string> accessedkeys;
	//set<string> updatedkeys;
	//set<string> deletedkeys;
	//int executions = aggregateaccess(appname, accessedkeys, updatedkeys, deletedkeys);

	//for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++) {
	//	TimeTravelStore::key_info_t key_info;
	//	if (ttstore->get_key_info_ex(it->c_str(), &key_info) != -1) {
	//		if (key_info.set_count > 0)
	//			keys.push_back(*it);
	//	}
	//}
	if (keys.size() > 0) {
		cerr << "Generating distance array:" << appname << "," << keys.size() << "," << m_clustering << "," << m_windowsize << "..." << endl;
		distmatrix = (double **)malloc(keys.size() * sizeof(double *));
		if (!distmatrix) {
			cerr << "Out of memory" << endl;
			return NULL;
		}
		for (int i = 0; i < keys.size(); i++) {
			distmatrix[i] = (double *)calloc(keys.size(), sizeof(double));
			if (!distmatrix[i]) {
				cerr << "Out of memory" << endl;
				return NULL;
			}
		}				

		if (output) {
			string outfilename(appname);
			outfilename += ".dist";
			ofstream ofs(outfilename.c_str());
			streambuf *orig = cerr.rdbuf(ofs.rdbuf());
			gendistarray(keys, distmatrix, 1);
			cerr.rdbuf(orig);
		} else {
			gendistarray(keys, distmatrix, 0);
		}
	}
    for (int i = 0; i < keys.size(); i++)
		for (int j = 0; j < keys.size(); j++)
			if (distmatrix[i][j] == 0)
				distmatrix[i][j] = NO_LINK;
	return distmatrix;
}

void TraceQuery::queryapp(const char *appname, int totalonly, int batch)
{

	set<string> accessedkeys;
	set<string> updatedkeys;
	set<string> deletedkeys;

	//double totalexecutiontime = 0.0;
	//int totalaccess = 0;
	//int totalupdate = 0;
	//int totaldelete = 0;
	cerr << "trace: " << tracename << endl;
	cerr << "application: " << appname << endl;
	int executions = aggregateaccess(appname, accessedkeys, updatedkeys, deletedkeys);

	if (batch) {
		vector<string> keys;
		for (set<string>::iterator it = accessedkeys.begin(); it != accessedkeys.end(); it++) {
			keys.push_back(*it);
		}

		listkeys(appname, "accessed", keys);
		return;
	}
	int totalevent = totalaccess + totalupdate + totaldelete;
	//if (accessedkeys.size() >= 20 && totalexecutiontime >= 30) {
	//if (totalevent >= 20) {
	//{
		cerr << "trace: " << tracename << endl;
		cerr << "appname: " << appname << endl;
		cerr << "\texecutions: " << executions << endl;
		cerr << "\texecution time: " << totalexecutiontime << " minutes" << endl;
		cerr << "\ttotal access: " << totalaccess << endl;
		cerr << "\ttotal update: " << totalupdate << endl;
		cerr << "\ttotal delete: " << totaldelete << endl;
		cerr << "\ttotal events: " << totalevent << endl;
		cerr << "\taccessed keys: " << accessedkeys.size() << endl;
		cerr << "\tupdated keys: " << updatedkeys.size() << endl;
		int i = 0;
#if 0
		for (set<string>::iterator it = accessedkeys.begin(); it != accessedkeys.end(); it++) {
				TimeTravelStore::key_info_t key_info;
				if (ttstore->get_key_info_ex(it->c_str(), &key_info) != -1)
					cerr << ++i << ". " << *it << ": " << key_info.get_count << ", " << key_info.set_count << endl;
				//else
				//	cerr << *it << endl;
		}
		cerr << "\tupdated keys: " << updatedkeys.size() << endl;
		cerr << "\tdeleted keys: " << deletedkeys.size() << endl;
#endif
		vector<string> keys;
		for (set<string>::iterator it = accessedkeys.begin(); it != accessedkeys.end(); it++) {
			keys.push_back(*it);
		}
		if (keys.size() > 0)
			listkeyvalues(appname, "accessed", keys);

		keys.clear();
		for (set<string>::iterator it = updatedkeys.begin(); it != updatedkeys.end(); it++) {
			keys.push_back(*it);
		}
		if (keys.size() > 0) {
			listkeyvalues(appname, "updated", keys);
		}

		set<string> accessedupdatedkeys;
		set_intersection(accessedkeys.begin(), accessedkeys.end(), updatedkeys.begin(), updatedkeys.end(), 
			inserter(accessedupdatedkeys, accessedupdatedkeys.begin()));
		cerr << "\taccessed & updated keys: " << accessedupdatedkeys.size() << endl;
		keys.clear();
		for (set<string>::iterator it = accessedupdatedkeys.begin(); it != accessedupdatedkeys.end(); it++) {
			keys.push_back(*it);
		}
		if (keys.size() > 0)
			listkeyvalues(appname, "accessedupdated", keys);

		set<string> accesseddeletedkeys;
		set_intersection(accessedkeys.begin(), accessedkeys.end(), deletedkeys.begin(), deletedkeys.end(), 
			inserter(accesseddeletedkeys, accesseddeletedkeys.begin()));
		cerr << "\taccessed & deleted keys: " << accesseddeletedkeys.size() << endl;
	//}
}

int TraceQuery::get_key_set_count(const char *key)
{
	TimeTravelStore::key_info_t key_info;
	if (!ttstore->get_key_info_ex(key, &key_info))
		return key_info.set_count;
	else
		return -1;
}

int TraceQuery::get_key_get_count(const char *key)
{
	TimeTravelStore::key_info_t key_info;
	if (!ttstore->get_key_info_ex(key, &key_info))
		return key_info.get_count;
	else
		return -1;
}

int TraceQuery::get_key_version_num(const char *key)
{
	return ttstore->get_num_versions(key, 0);
}

void TraceQuery::rankkeys(vector<int>& keys, list<keyranking>& rankedkeys, int time, RankPolicy policy, const char *key)
{
	rankedkeys.clear();
#if 0
	list<int> numupdates;
	for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++) {
		TimeTravelStore::key_info_t keyinfo;
		if (ttstore->get_key_info_ex(it->c_str(), &keyinfo)) {
			cerr << "Failed to get key info for " << it->c_str() << endl;
			continue;
		}
		numupdates.push_back(ttstore->get_num_versions(it->c_str(), time));
	}
	numupdates.sort();

	list<keyranking> byratio;
	int highestupdates = numupdates.back();
	//int threshold = threshold * highestupdates;
	for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++) {
		num_versions = ttstore->get_num_versions(it->c_str(), time);
		if (num_versions < threshold) {
				insertkeyranking(rankedkeys, it->c_str(), num_versions, 1);
		} else {
				double ratio = getratio(getclusterratioit->c_str(), num_versions);
				insertkeyranking(byratio, it->c_str(), ratio, 1);
		}
	}
#else
	for (vector<int>::iterator it = keys.begin(); it != keys.end(); it++) {
		int num_versions;// = ttstore->get_num_versions(it->c_str(), time);
		double ratio = getclusterratio(*it, num_versions);
		list<double> times;
		int keyid;
		switch(policy) {
			case POLICY_BYUPDATE:
				//ranking = keyinfo.set_count;
				insertkeyranking(rankedkeys, *it, num_versions, ratio, num_versions, 1);
				break;
			case POLICY_BYRATIO:
				//ranking = (double)keyinfo.set_count/keyinfo.get_count;
				insertkeyranking(rankedkeys, *it, ratio, 0, num_versions, 1);
				break;
			case POLICY_BYHYBRID:
				times.clear();
				keyid = m_clusterslink[*it][0];
				if (m_latestkeysettime < m_time_bound * 24 * 60 * 60)
					m_time_bound = 0;
				if (ttstore->get_timestamps(id2key(keyid), (m_time_bound ? m_latestkeysettime - m_time_bound * 24 * 60 * 60 : 0), times) == -1) {
					cerr << "Error calling get_timestamps on " << id2key(keyid) << endl;
				} else {
					times.sort();
					if (keyincluster(key, *it)) {
						// inject writes for offending cluster
						if (num_versions < multiple_writes) {
							num_versions = multiple_writes;
						}
						double latest = times.back();
						int count = multiple_writes - times.size();
						if (count > 0) {
							for (int i = 0; i < count; i++) {
								times.push_back(latest + i + 1);
							}
						} else if (count < 0) {
							for (int i = count; i < 0; i++)
								times.pop_back();
						}
						for (int i = 0; i < multiple_writes; i ++) {
							times.pop_back();
						}
						for (int i = 0; i < multiple_writes; i ++) {
							times.push_back(time + i);

						}
					}
					//insertkeyranking(rankedkeys, *it, num_versions, times.back(), 1);
					if (times.size() > 0)
						insertkeyranking(rankedkeys, *it, num_versions, times.back(), times.size(), 1);
				}
				break;
			default:
				break;
		}
	}
#endif
}

int TraceQuery::resetkey(const char *key)
{
	return ttstore->set_current_version(key, -1);
}

// flag: 0 - return number of versions
//       1 - rollback key for one version
int TraceQuery::rollbackkey(const char *key, int time, int flag, char *pdata, int *pdatalen, int *ptype, double *ptimestamp)
{
	//if (time == 0)
	//	return get_key_version_num(key);

    int numrollbacks = 0;
	TimeTravelStore::key_info_t key_info;
	if (!ttstore->get_key_info_ex(key, &key_info)) {
		if (flag == 0) {
			int num = ttstore->get_num_versions(key, time);
			if (num >= 0) {
				numrollbacks = num;
			} else
				cerr << "Failed to call get_num_versions for " << key << endl;
		} else {
			ttstore->rollback_value(key);
			ttstore->get_value(key, -1, pdata, pdatalen, ptype, ptimestamp, 1);
		}
	} else
		cerr << "Failed to get key info for " << key << endl;
	return numrollbacks;
}

void TraceQuery::insertkeyranking(list<keyranking>& updates, int key, double ranking, double ratio, int versions, int order)
{
	keyranking update;

	//strcpy(update.key, key);
	update.key = key;
	update.ranking = ranking;
	update.ratio = ratio;
	update.versions = versions;

	list<keyranking>::iterator it;
	for (it = updates.begin(); it != updates.end(); it++) {
		if (0 == order) {
			if (ranking > it->ranking) {
				break;
			}
		} else {
			if (ranking < it->ranking) {
				break;
			} else if (ranking == it->ranking) {
				//if (ratio < it->ratio)
				if (ratio > it->ratio)
					break;
			}
		}
	}
	if (it == updates.end())
		updates.push_back(update);
	else {
		updates.insert(it, update);
	}
}

bool comp_keyranking(const TraceQuery::keyranking& first, const TraceQuery::keyranking& second)
{
	if (first.ranking <= second.ranking)
		return false;
	else
		return true;
}

int TraceQuery::rollbackbytime(const char *appname, const char *key, vector<int>& clusters, int time)
{
	list<keyranking> updates;

	int cost = 0;
	set<string> rollbackedkeys;
	int processed = 0;
	int i = 0;

	m_collateraldamage_bytime.clear();
	for (int i = 0; i < clusters.size(); i++) {
//		if (time) {
//			if (strcmp(it->c_str(), key) == 0)
//				continue;
//		}
		list<double> times;
		for (vector<int>::iterator it = m_clusterslink[i].begin(); it != m_clusterslink[i].end(); it++) {
			if (ttstore->get_timestamps(id2key(*it), 0, times) != -1) {
				times.sort();
				//for (list<double>::iterator dit = times.begin(); dit != times.end(); dit++) {
					//if (*dit >= time) {
					if (times.back() >= time) {
						//insertkeyranking(updates, it->c_str(), *dit, 0);
					
						keyranking update;
						//strcpy(update.key, it->c_str());
						update.key = i;
						//update.ranking = *dit;
						update.ranking = times.back();
						updates.push_back(update);
						//break;
					}
				//}
			} else
				cerr << "Failed to get value for " << id2key(*it) << endl;
		}
	}
	// rollback
	updates.sort(comp_keyranking);
	string latesttime, rollbacktime;
	for (list<keyranking>::iterator it = updates.begin(); it != updates.end(); it++) {
		//if (strcmp(id2key(it->key), key) == 0) {
		int version = 0;
		getclusterratio(it->key, version);
		if (keyincluster(key, it->key)) {
			rollbacktime = time2str((int)it->ranking);
			cerr << "* rollback: " << it->key << "@" << rollbacktime << ", " << version << endl;
			//break;
		} else {
			cerr << "  rollback: " << it->key << "@" << time2str((int)it->ranking) << ", " << version << endl;
			cost++;
			for (vector<int>::iterator cit = m_clusterslink[it->key].begin(); cit != m_clusterslink[it->key].end(); cit++) {
				m_collateraldamage_bytime.insert(id2key(*cit));
			}
			if (latesttime == "")
				latesttime = time2str((int)it->ranking);
		}
	}
	//if (m_interactive)
		cerr << "cost & keys, " << cost << ", " << rollbackedkeys.size() << ", " << rollbacktime << ", " << latesttime << endl;
	return cost;
}

int TraceQuery::rollbackbyrankingex(const char *appname, const char *key, vector<int>& clusters, int time, RankPolicy policy)
{
	list<keyranking> rankedkeys;
	rankkeys(clusters, rankedkeys, time, policy, key);

	int cost = 0;
	int numrollbackedkeys = 0;
	int writes = 0;
	// rollback
	cerr << "rollbackbyrankingex #clusters:" << rankedkeys.size() << endl;
	if (rankedkeys.size() == 0)
		return 0;

	int rollbacks = 0;
	bool fixed = false;
	m_clustersrollbacks.clear();
	m_rollbackkeys.clear();
	while (1) {
		int any_keycost = 0;
		for (list<keyranking>::iterator it = rankedkeys.begin(); it != rankedkeys.end(); it++) {
			// assumes BYHYBRID
			if (m_clustersrollbacks.find(it->key) == m_clustersrollbacks.end())
				m_clustersrollbacks[it->key] = it->versions;
			int keycost = 0;
			if (m_clustersrollbacks[it->key] > 0) {
				switch(traverse_policy) {
				case BREADTH_FIRST:
					keycost = 1;
					m_clustersrollbacks[it->key] --;
					break;
				case DEPTH_FIRST:
					keycost = m_clustersrollbacks[it->key];
					m_clustersrollbacks[it->key] = 0;
					break;
				}
				list<string> keys;
				stringstream ss;
				ss << keycost;
				keys.push_back(ss.str());
				for (vector<int>::iterator cit = m_clusterslink[it->key].begin(); cit != m_clusterslink[it->key].end(); cit++) {
					keys.push_back(id2key(*cit));
				}
				if (!fixed)
					cost += keycost;
				if (keyincluster(key, it->key)) {
					cerr << "* rollback cluster (" << keycost << ")" << " : " << it->key << ", " << it->ranking << ", " << it->ratio << endl;
					rollbacks += keycost;
					if (rollbacks == multiple_writes)
						fixed = true;
					keys.push_front("*");
				} else {
					cerr << "  rollback cluster (" << keycost << ")" << " : " << it->key << ", " << it->ranking << ", " << it->ratio << endl;
					keys.push_front(" ");
				}
				//if (!fixed)
					m_rollbackkeys.push_back(keys);
				//numrollbackedkeys ++;
			}
			any_keycost += keycost;
		} // end for
		if (!any_keycost)
			break;
	} // end while
	// if (m_interactive)
	//	cerr << "cost & keys, " << cost << ", " << numrollbackedkeys << endl;
	return cost;
}

int TraceQuery::rollbackbyranking(const char *appname, const char *key, vector<int>& clusters, int time, RankPolicy policy)
{
	int cost = 0;

	if (policy == POLICY_BYHYBRID) {
		bool needRollbackhighclusters = false;

		vector<int> lowclusters, highclusters;
		for (int i = 0; i < clusters.size(); i++) {
			int num_versions;// = ttstore->get_num_versions(it->c_str(), time);
			double ratio = getclusterratio(i, num_versions);
			if (ratio <= m_threshold)
				lowclusters.push_back(i);
			else {
				highclusters.push_back(i);
				if (keyincluster(key, i))
					needRollbackhighclusters = true;
			}
		}
		cerr << "# ratio <= " << m_threshold << endl;
		cost = rollbackbyrankingex(appname, key, lowclusters, time, policy);
		if (needRollbackhighclusters) {
			cerr << "# ratio > " << m_threshold << endl;
			cost += rollbackbyrankingex(appname, key, highclusters, time, policy);
		}
	} else {
		cost = rollbackbyrankingex(appname, key, clusters, time, policy);
    }
	return cost;
}

// mode: 0 means interactive mode
void TraceQuery::calcrollbackcost(const char *appname, const char *key, vector<string>& keys, int time)
{
	int costbytime = 0, costbyupdates = 0, costbyratio = 0, costbyhybrid = 0;
	vector<int> clusters;

	// prepare m_keys for id2key()
	m_keys = keys;
	//

	if (m_interactive) {
		cerr << tracename << ", " << "rollback by time, " << key << ", ";
	}
    	if (m_clustering) {
		for (int i = 0; i < m_clusterslink.size(); i++)
			clusters.push_back(i);
	} else {
		for (int i = 0; i < keys.size(); i++)
			clusters.push_back(i);
	}
	cerr << "# statistics of ratios" << endl;
	double min_ratio = 9999.99;
	double max_ratio = 0.0;
	double total_ratio = 0.0;
	int min_updates = 9999;
	int max_updates = 0;
	int total_updates = 0;
	for (int i = 0; i < clusters.size(); i++) {
		int updates = 0;
		double ratio = getclusterratio(i, updates);
		total_ratio += ratio;
		total_updates += updates;
		if (ratio < min_ratio)
			min_ratio = ratio;
		if (ratio > max_ratio)
			max_ratio = ratio;
		if (updates < min_updates)
			min_updates = updates;
		if (updates > max_updates)
			max_updates = updates;
	}
	cerr << "# stat, " << clusters.size() << ", " << min_ratio << ", " << total_ratio / clusters.size() << ", " << max_ratio << ", " << min_updates << ", " << total_updates / clusters.size() << ", " << max_updates << endl;

	if (rollback_strategy & ROLLBACK_BYTIME) {
		cerr << "# rollback by time" << endl;
		costbytime = rollbackbytime(appname, key, clusters, time);
		if (m_interactive) {
			cerr << tracename << ", " << "rank by updates, " << key << ", ";
		}
	}
/*
	cerr << "# rank by updates" << endl;
	costbyupdates = rollbackbyranking(appname, key, clusters, 0, POLICY_BYUPDATE);
	if (m_interactive) {
		cerr << tracename << ", " << "rank by ratio, " << key << ", ";
	}
	cerr << "# rank by ratio" << endl;
	costbyratio = rollbackbyranking(appname, key, clusters, 0, POLICY_BYRATIO);
	if (m_interactive) {
		cerr << tracename << ", " << "rank by hybrid, " << key << ", ";
	}
*/
	if (rollback_strategy & ROLLBACK_BYHYBRID) {
		cerr << "# rank by hybrid" << endl;
		costbyhybrid = rollbackbyranking(appname, key, clusters, time, POLICY_BYHYBRID);
	}
	//if (m_interactive) {
	//	cout << (double)costbyupdates/costbytime << ", " << (double)costbyratio/costbytime << ", " << (double)costbyhybrid/costbytime << endl;
	//}
	if (m_interactive)
		cout << tracename << ", " << appname << ", " << costbytime << ", " << costbyratio << ", " << costbyhybrid << ", " << m_threshold << ", " << key << endl;
	else
		cerr << tracename << ", " << appname << ", " << costbytime << ", " << costbyratio << ", " << costbyhybrid << ", " << m_threshold << ", " << key << endl;
	m_costbytime = costbytime;
	m_costbyratio = costbyratio;
	m_costbyhybrid = costbyhybrid;
}

double TraceQuery::getlatestkeysettime(vector<string>& keys)
{
	list<keyranking> updates;
	list<double> times;
	int i = 0;

	for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++) {
		int num = ttstore->get_timestamps(it->c_str(), 0, times);
		if (num > 0) {
				for (list<double>::iterator dit = times.begin(); dit != times.end(); dit++) {
					keyranking update;
					//strcpy(update.key, it->c_str());
					update.key = i;
					update.ranking = *dit;
					updates.push_back(update);
				}
		} else
			cerr << "Failed to get value for " << it->c_str() << endl;
		i++;
	}
	updates.sort(comp_keyranking);
	return updates.front().ranking;
}


//remvoe keys that have no versions
void TraceQuery::removeconstkeys(vector<string>& keys)
{
	vector<string>::iterator it = keys.begin();
	while (it != keys.end()) {
		if (get_key_set_count(it->c_str()) == 0) {
			//cerr << "Removed constant key " << it->c_str() << endl;
			it = keys.erase(it);
		} else
			++it;
	}
}

int TraceQuery::getaccessedversionedkeys(const char *appname, vector<string>& accessedkeys)
{
	accessedkeys.clear();
	//int numaccessedkeys = appstore->getaccessedkeys(appname, NULL, accessedkeys);
	//if (numaccessedkeys == 0) {
		set<string> keys;
		vector<string> pids;
		appstore->getproc(appname, pids);
		vector<string> tkeys;
		for (vector<string>::iterator it = pids.begin(); it != pids.end(); it++) {	
			int numaccessedkeys = appstore->getaccessedkeys(appname, it->c_str(), tkeys);
			for (vector<string>::iterator  tit = tkeys.begin(); tit != tkeys.end(); tit++)
				keys.insert(*tit);
		}
		for (set<string>::iterator it = keys.begin(); it != keys.end(); it++)
			accessedkeys.push_back(*it);
	//}
	removeconstkeys(accessedkeys);
	return accessedkeys.size();
}

void TraceQuery::testrollback(const char *appname, int id, int days, int writes)
{
	vector<string> keys;
	getaccessedversionedkeys(appname, keys);

	multiple_writes = writes;
	int latesttime = (int)getlatestkeysettime(keys);
	m_latestkeysettime = latesttime;
	int numaccessedkeys = keys.size();
	if (numaccessedkeys > 0) {
		if (m_clustering)
			m_clustersrollbacks.clear();
		if (!m_interactive) {
#if 0
			char *copykey = new char[TimeTravelStore::max_key_len];
			assert(copykey);
			sprintf(copykey, "%s.copy", keys[id - 1].c_str());
			if (days > 0) {
				if (ttstore->copy_key(keys[id - 1].c_str(), copykey, 0)) {
					cout << "Copy key " << keys[id - 1].c_str() << " failed" << endl;
					goto bail;
				}
				ttstore->set_latest_timestamp(keys[id - 1].c_str(), latesttime - days * 24 * 60 * 60);
			}
#endif
			calcrollbackcost(appname, keys[id - 1].c_str(), keys, latesttime - days * 24 * 60 * 60);
			//calcrollbackcost(appname, keys[id - 1].c_str(), keys, 0);
#if 0
			if (days > 0) {
				ttstore->copy_key(copykey, keys[id - 1].c_str(), 0);
			}
#endif
bail:
#if 0
			if (copykey)
				delete[] copykey;
#endif
			return;
		}
		//listkeys(tracename, appname, "accessed keys", keys);
		do {
			cout << "Choose a key (1 to " << numaccessedkeys << ", 0 for exit, or -1 to list keys): ";
			char buf[80];
			cin >> buf;
			int id = atoi(buf);
			if (id == 0)
				break;
			else if (id == -1) {
				listkeys(appname, "accessedversioned", keys);
				continue;
			}
			cout << "Is it the right key \"" << keys[id - 1] << "\" (y/n)? ";
			cin >> buf;
			if (buf[0] == 'y' || buf[0] == 'Y') {
				int time = -1;
				do {
					cout << "Choose the time of offending change (0 - in trace, N - N day ago, -1 to exit): ";
					char input[80];
					cin >> input;
					int choice = atoi(input);

					if (choice >= 1 && choice <= 31) {
						time = latesttime - choice * 24 * 60 * 60;
						break;
					} else if (choice == 0) {
						time = 0;
						break;
					} else if (choice == -1)
						break;
					else
						cout << "Invalid choice, try again" << endl;
				} while (1);
				cout << "Choose threshold: ";
				char input[80];
				cin >> input;int latesttime = (int)getlatestkeysettime(keys);
				setthreshold(atof(input));
#if 0
				char *copykey = NULL;
				if (time > 0) {
					copykey = new char[TimeTravelStore::max_key_len];
					assert(copykey);
					sprintf(copykey, "%s.copy", keys[id - 1].c_str());
					if (ttstore->copy_key(keys[id - 1].c_str(), copykey, 0)) {
						cout << "Copy key " << keys[id - 1].c_str() << " failed" << endl;
						delete[] copykey;
						break;
					}
					ttstore->copy_key(copykey, keys[id - 1].c_str(), 0);
					ttstore->set_latest_timestamp(keys[id - 1].c_str(), time);
				}
#endif
				cout << "rollback until " << time2str(time) << " (" << time2str(latesttime) << ")" << endl;
				calcrollbackcost(appname, keys[id - 1].c_str(), keys, time);
#if 0
				if (time > 0) {
					ttstore->copy_key(copykey, keys[id - 1].c_str(), 0);
					if (copykey)
						delete[] copykey;
				}
#endif
				break;
			}
		} while (1);
	} else
		cout << appname << " does not access any key, is the application name correct?" << endl;
}

void TraceQuery::menuapp(const char *appname)
{
	int cont = 1;
	
	if (strcmp(appname, "*") == 0) {
		vector<string> apps;
		appstore->getapp(apps);
		for (vector<string>::iterator it = apps.begin(); it != apps.end(); it++) {
			cout << "Querying information on " << it->c_str() << endl;
			queryapp(it->c_str(), 1);
		}
	} else {
		do {
			cout << "1. Query keys accessed by application" << endl;
			cout << "2. Test rollback" << endl;
			cout << "Enter choice (0 to exit): ";
			char buf[80];
			cin >> buf;
			int choice = atoi(buf);
			switch(choice) {
			case 0:
				cont = 0;
				break;
			case 1:
				queryapp(appname, 1);
				break;
			case 2:
				testrollback(appname);
				break;
			default:
				cout << "Invalid choice" << endl;
				break;
			}
		} while (cont);
	}
}

void TraceQuery::listapps(std::vector<std::string>& apps)
{
	appstore->getapp(apps);
}

void TraceQuery::setthreshold(double threshold)
{
	m_threshold = threshold;
}

void TraceQuery::setinteractive(bool flag)
{
	m_interactive = flag;
}

/*
	//strcpy(appname, "AcroRd32.exe");
#if 0
	// test replay
	appstore->startproc(appname, "3512", 1);
	appstore->accesskey(appname, "3512", "SOFTWARE\\Policies\\Adobe\\Acrobat Reader\\10.0\\FeatureLockDown\\bUseReadPolicy", 2);
	appstore->updatekey(appname, "3512", "SOFTWARE\\Policies\\Adobe\\Acrobat Reader\\10.0\\FeatureLockDown\\bUseWhitelistConfigFile", 3);
	appstore->createkey(appname, "3512", "Software\\Adobe\\Acrobat Reader\\10.0\\Privileged\\bUseReadPolicy", 4);
	appstore->deletekey(appname, "3512", "Software\\Adobe\\Acrobat Reader\\10.0\\Installer\\Path", 5);
	appstore->accesskey(appname, "3512", "SOFTWARE\\Policies\\Adobe\\Acrobat Reader\\10.0\\FeatureLockDown\\bUseWhitelistConfigFile", 8);
	appstore->createproc(appname, "3512", "AdobeARM.exe", "4308", 10);
	appstore->exitproc(appname, "3512", 15);
#endif

#if 0
	map<string, void *> cache;
	cache["file"] = NULL;
	cache["file1"] = &cache;
	printf("%p\n", cache["file"]);
	printf("%p\n", cache["file1"]);
#endif

*/

int TraceQuery::enumkeys(const char *pattern, std::vector<std::string>& keys)
{
	return ttstore->matchkeys(pattern, keys);
}

int TraceQuery::getdistkeypair(const std::string& key1, const std::string& key2, double earliestime, int &update1, int &update2)
{
	static map<string, list<double> > cached_times;
	list<double> times1, times2;
	static map<string, map<double, int> > cached_timesmap;
	map<double, int> times1map, times2map;
	int dist = 0;
	static map<string, int> keymap;
	int prtkey1times = 0, prtkey2times = 0;
	int ret;

	if (cached_timesmap.find(key1) != cached_timesmap.end())
		times1map = cached_timesmap[key1];
	else {
		times1map.clear();
		if (m_clusteringmode == 0)
			ret = ttstore->get_timestamps(key1.c_str(), 0, times1);
		else
			ret = ttstore->get_read_timestamps(key1.c_str(), 0, times1);
		if (!ret) {
			cerr << "get_timestamps failed on " << key1 << endl;
			return 0;
		}
		for (list<double>::iterator it = times1.begin(); it != times1.end(); it++) {
			double reltime = *it - earliestime;
			if (reltime == 0)
				continue;
			int window = reltime/m_windowsize;
			times1map[window] = 1;
	#ifdef DEBUG
			if (prtkey1times) {
				if (it == times1.begin())
					cerr << "*" << key1 << "(" << times1.size() << ")";
				//cerr << ", " << *it;
			}
	#endif
		}
		if (prtkey1times && times1.size() > 0)
			cerr << endl;

		cached_timesmap[key1] = times1map;
	}
	if (cached_timesmap.find(key2) != cached_timesmap.end())
		times2map = cached_timesmap[key2];
	else {
		times2map.clear();
		if (m_clusteringmode == 0)
			ret = ttstore->get_timestamps(key2.c_str(), 0, times2);
		else
			ret = ttstore->get_read_timestamps(key2.c_str(), 0, times2);
		if (!ret) {
			cerr << "get_timestamps failed on " << key2 << endl;
			return 0;
		}
		for (list<double>::iterator it = times2.begin(); it != times2.end(); it++) {
			double reltime = *it - earliestime;
			if (reltime == 0)
				continue;
			int window = reltime/m_windowsize;
			times2map[window] = 1;
	#ifdef DEBUG
			if (prtkey2times) {
				if (it == times2.begin())
					cerr << "*" << key2 << "(" << times2.size() << ")";
				//cerr << ", " << *it;
			}
	#endif
		}
	#ifdef DEBUG
		if (prtkey2times && times2.size() > 0)
			cerr << endl;
	#endif

		cached_timesmap[key2] = times2map;
	}
	//if (times1.size() > 1 || times2.size() > 1)
	//	cout << "debug here" << endl;
#ifdef DEBUG
	if (keymap.find(key1) == keymap.end()) {
		keymap[key1] = 1;
		prtkey1times = 1;
	}
	if (keymap.find(key2) == keymap.end()) {
		keymap[key2] = 1;
		prtkey2times = 1;
	}
#endif

	for (map<double, int>::iterator it = times1map.begin(); it != times1map.end(); it++) {
		if (times2map.find(it->first) != times2map.end())
			dist ++;
	}
	update1 = times1map.size();
	update2 = times2map.size();

	return dist;
}

int TraceQuery::gendistarray(std::vector<string>& keys, double **distmatrix, int output)
{
	double earliestime;

	if (m_clusteringmode == 0)
		earliestime = getearliestkeysettime(keys);
	else
		earliestime = getearliestkeygettime(keys);

	//double earliestime = 0;
	int update1 = 0, update2 = 0;
	for (int i = 0; i < keys.size(); i++) {
		for (int j = i + 1; j < keys.size(); j++) {
			int dist = getdistkeypair(keys[i], keys[j], earliestime, update1, update2);
			double normalized_dist = 0;
			if (dist)
				normalized_dist = 1/ ((double)dist/update1 + (double)dist/update2);
			distmatrix[i][j] = normalized_dist;
			distmatrix[j][i] = normalized_dist;
			if (output)
				cerr << keys[i] << ", " << update1 << ", " << keys[j] << ", " << update2 << ", " << dist << endl;
		}
	}
	return 0;
}

double TraceQuery::getearliestkeysettime(vector<string>& keys)
{
	list<keyranking> updates;
	list<double> times;
	int i = 0;

	for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++) {
		int num = ttstore->get_timestamps(it->c_str(), 0, times, 0);
		if (num > 0) {
				for (list<double>::iterator dit = times.begin(); dit != times.end(); dit++) {
					keyranking update;
					//strcpy(update.key, it->c_str());
					update.key = i;
					update.ranking = *dit;
					updates.push_back(update);
				}
		} else
			cerr << "Failed to get value for " << it->c_str() << endl;
		i++;
	}
	updates.sort(comp_keyranking);
	return updates.back().ranking;
}

double TraceQuery::getearliestkeygettime(vector<string>& keys)
{
	double earliestime = time(NULL);	

	for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++) {
		list<double> times;
		int num = ttstore->get_read_timestamps(it->c_str(), 0, times);
		if (num > 0) {
				for (list<double>::iterator dit = times.begin(); dit != times.end(); dit++) {
					if (*dit < earliestime)
						earliestime = *dit;
				}
		} else
			cerr << "Failed to get value for " << it->c_str() << endl;
	}
	return earliestime;
}

const char *TraceQuery::id2key(int id) const
{
	return m_keys[id].c_str();
}

int TraceQuery::setclustering(const char *appname, double clustering, int windowsize, int mode)
{
	int ret = 0;
	vector<string> keys;
	if (!mode) // mode = 0: for writes
		getaccessedversionedkeys(appname, keys);
	else
		getaccessedkeys(appname, keys);

	for (int i = 0; i < keys.size(); i++) {
		TimeTravelStore::key_info_t key_info;
		if (ttstore->get_key_info_ex(keys[i].c_str(), &key_info) != -1) {
			int num_versions = ttstore->get_num_versions(keys[i].c_str(), 0);
			cerr << i + 1 << ", " << keys[i] << ", " << (double)num_versions/key_info.get_count << ", " << key_info.get_count << ", " << num_versions << ", " << key_info.set_count << endl; 
		} else {
			cerr << "Error calling get_key_info_ex on " << keys[i] << endl;
		}			
	}
	m_clustering = clustering;
	m_windowsize = windowsize;
	m_clusteringmode = mode;
	if (clustering) {
		double **distmatrix = calckeydist(appname, keys, 1);

		m_clusterslink.clear();
		ret = cluster(distmatrix, keys.size(), keys, 0, m_clusterslink, clustering);
		if (ret > 0)
			dispclusters(keys, m_clusterslink);
		else
			ret = -1;
		for (int i = 0; i < keys.size(); i++) {
			free(distmatrix[i]);
		}
		free(distmatrix);
	}
	return ret;
}

int TraceQuery::getclusters(std::vector<std::vector<int> >& clusters) {
	clusters = m_clusterslink;
	return clusters.size();
}

double TraceQuery::getclusterratio(int cluster, int &num_versions)
{
	int tot_num_versions = 0;
	int count = 0;
	double tot_ratio = 0.0;
	double ratio = 0.0;

	if (m_clustering) {
		//cerr << "cluster " << cluster << endl;
		double lowest_ratio = 9999.99;
		for (vector<int>::iterator it = m_clusterslink[cluster].begin(); it != m_clusterslink[cluster].end(); it++) {
			int num_versions;
			double ratio = getratio(id2key(*it), num_versions);
			//cerr << "\tkey" << *it + 1 << ", " << id2key(*it) << ", ratio: " << ratio << ", updates: " << num_versions << endl;
			if (ratio < lowest_ratio)
				lowest_ratio = ratio;
			tot_ratio += ratio;
			tot_num_versions += num_versions;
			count ++;
		}
		// average updates
		num_versions = tot_num_versions / count;
		// total updates
		//num_versions = tot_num_versions;
		// average
		// ratio = tot_ratio / count;
		// minimum
		ratio = lowest_ratio;
	    //cerr << "cluster " << cluster << ", ratio: " << ratio << ", updates: " << num_versions << endl;
	} else {
		int key = cluster;
		ratio = getratio(id2key(key), num_versions);
		//cerr << "key " << key << ", ratio: " << ratio << ", updates: " << num_versions << endl;
	}
	return ratio;
}

bool TraceQuery::keyincluster(const char *key, int cluster)
{
	if (m_clustering) {
		for (vector<int>::iterator it = m_clusterslink[cluster].begin(); it != m_clusterslink[cluster].end(); it++) {
			if (strcmp(id2key(*it), key) == 0)
				return true;
		}
		return false;
	} else
		return (strcmp(id2key(cluster), key) == 0);
}

int TraceQuery::rollbackcluster(int cluster, int time, int flag, char *pdata, int *pdatalen, int *ptype, double *ptimestamp)
{
	int max_rollbacks = 0;
	int tot_rollbacks = 0;

	if (m_clustering) {
		// max rollbacks is not really right, should be:
		// for a cluster with two keys: key1 and key2
		// each of them were updated for 4 times, 3 out which they were updated together
		// the total number of rollbacks would be 5 instead of 4 (max rollbacks for a key)
		if (m_clustersrollbacks.find(cluster) == m_clustersrollbacks.end()) {
			for (vector<int>::iterator it = m_clusterslink[cluster].begin(); it != m_clusterslink[cluster].end(); it++) {
				int rollbacks = rollbackkey(id2key(*it), time, 0);
				cerr << "rollback: " << *it << ". " << id2key(*it) << ", " << rollbacks << ", " << endl;
				if (rollbacks > max_rollbacks)
					max_rollbacks = rollbacks;
			}
			tot_rollbacks = max_rollbacks;
			m_clustersrollbacks[cluster] = tot_rollbacks;
		}
		//cerr << "==== " << __FUNCTION__ << " cluster " << cluster << ":" << m_clustersrollbacks[cluster] << endl;
	} else {
		int key = cluster;
		int rollbacks = rollbackkey(id2key(key), time, 0);
		cerr << "rollback: " << key << ". " << id2key(key) << ", " << rollbacks << ", " << endl;
		tot_rollbacks = rollbacks;
	}
	return tot_rollbacks;
}

void TraceQuery::settraversepolicy(TraversePolicy policy)
{
	traverse_policy = policy;
}

void TraceQuery::setrollbackstrategy(int strategy)
{
	rollback_strategy = strategy;
}

void TraceQuery::settimebound(double time_bound)
{
	m_time_bound = time_bound;
}

int TraceQuery::get_current_version(const char *key)
{
	return ttstore->get_current_version(key);
}

int TraceQuery::set_key_value(const char *key, int version, const char *value, int valuelen, int type, double timestamp)
{
	return ttstore->update_value(key, version, value, valuelen, type, timestamp);
}

int TraceQuery::get_key_value(const char *key, int version, char *value, int *valuelen, int *type, double *timestamp)
{
	return ttstore->get_value(key, version, value, valuelen, type, timestamp, 1);
}

int TraceQuery::get_key_timestamps(const char *key, double timestamp, std::list<double>& times, int check_dup)
{
	return ttstore->get_timestamps(key, timestamp, times, check_dup);
}

double TraceQuery::getclustering()
{
	return m_clustering;
}

int TraceQuery::getwindowsize()
{
	return m_windowsize;
}

int TraceQuery::getavgclustersize()
{
	if (m_clusterslink.size() > 0)
		return m_keys.size()/m_clusterslink.size();
	else
		return 0;
}

int TraceQuery::getkeycount()
{
	return m_keys.size();
}

bool TraceQuery::keyidincluster(int keyid, int cluster)
{
	if (m_clustering) {
		for (vector<int>::iterator it = m_clusterslink[cluster].begin(); it != m_clusterslink[cluster].end(); it++) {
			if (*it == keyid)
				return true;
		}
		return false;
	} else
		return (cluster == keyid);
}

int TraceQuery::getaccessedkeys(const char *appname, vector<string>& accessedkeys)
{
	accessedkeys.clear();
		set<string> keys;
		vector<string> pids;
		appstore->getproc(appname, pids);
		vector<string> tkeys;
		for (vector<string>::iterator it = pids.begin(); it != pids.end(); it++) {	
			int numaccessedkeys = appstore->getaccessedkeys(appname, it->c_str(), tkeys);
			for (vector<string>::iterator  tit = tkeys.begin(); tit != tkeys.end(); tit++)
				keys.insert(*tit);
		}
		for (set<string>::iterator it = keys.begin(); it != keys.end(); it++)
			accessedkeys.push_back(*it);

	return accessedkeys.size();
}


