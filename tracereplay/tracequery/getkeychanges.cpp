// getupdatestat.cpp
// Note that getupdatestat.ext happens to be the name of a protected Windows application, so we 
// have to change our executable name to getkeychanges on Windows
// calculate statistics on keys' updates
#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "../libtracequery/tracequery.h"

using namespace std;

TraceQuery tracequery;

void getupdatestat(char *server, char *trace, vector<string>& keys) {
	set<double> updates;

	//cout << "server:" << server << endl;
	//cout << "trace:" << trace << endl;
	tracequery.init(server);
	tracequery.settrace(trace);
	for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++) {
		list<double> times;
		if (tracequery.get_key_timestamps(it->c_str(), 0, times) != -1) {
			//cout << '\t' << it->c_str() << endl;			
			for (list<double>::iterator iit = times.begin(); iit != times.end(); iit++)
				updates.insert(*iit);
		} else
			cerr << "Failed to get timestamps for " << it->c_str() << endl;
	}
	double prev, max = 0, min = time(NULL), sum = 0, count = 0, avg;
	for (set<double>::iterator it = updates.begin(); it != updates.end(); it++) {
		if (it == updates.begin()) {
			prev = *it;
			continue;
		}
		double interval = *it - prev;
		if (interval > max)
			max = interval;
		if (interval < min)
			min = interval;
		sum += interval;
		count ++;
	}
	if (count > 0)
		avg = sum / count;
	else {
		avg = sum;
		min = sum;
	}
	double hour = 60 * 60;
	cout << "max:" << max/hour << ' ' << max/hour/24 << endl;
	cout << "min:" << min/hour << ' ' << min/hour/24 << endl;
	cout << "avg:" << avg/hour << ' ' << avg/hour/24 << endl;
}

void getupdatestat2(char *server, char *trace, vector<string>& keys) {
	map<string, list<double> > key_updates;
	double latest_update = 0;

	//cout << "server:" << server << endl;
	//cout << "trace:" << trace << endl;
	tracequery.init(server);
	tracequery.settrace(trace);
	for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++) {
		list<double> times;
		if (tracequery.get_key_timestamps(it->c_str(), 0, times) != -1) {
			//cout << '\t' << it->c_str() << endl;
			// if we can assume times are sorted from earliest to latest, then we can just insert times.begin()
			for (list<double>::iterator iit = times.begin(); iit != times.end(); iit++) {
				key_updates[*it] = times;
				if (*iit > latest_update)
					latest_update = *iit;
			}
		} else
			cerr << "Failed to get timestamps for " << it->c_str() << endl;
	}
	int one_day = 60 * 60 * 24;
	int latest_day = (latest_update / one_day) + 1;
	set<string> buckets[30];
	for (map<string, list<double> >::iterator it = key_updates.begin(); it != key_updates.end(); it++) {
		for (list<double>::iterator iit = it->second.begin(); iit != it->second.end(); iit++) {
			int days = (int)(latest_update - *iit) / one_day;
			if (days < 30)
				buckets[days].insert(it->first);
		}
	}
	int sum = 0;
	set<string> all;
	for (int i = 0; i < 30; i++) {
		if (i == 0) {
			sum += buckets[i].size();
			for (set<string>::iterator it = buckets[i].begin(); it != buckets[i].end(); it++)
				all.insert(*it);
		} else {
			int count = 0;
			for (set<string>::iterator it = buckets[i].begin(); it != buckets[i].end(); it++) {
				if (all.find(*it) == all.end()) {
					count ++;
					all.insert(*it);
				}
			}
			sum += count;
		}
		//cout << i << ", " << sum;
		cout << sum;
/*
		for (set<string>::iterator it = buckets[i].begin(); it != buckets[i].end(); it++) {
			if (it == buckets[i].begin())
				cout << ", " << it->c_str();
			else
				cout << ", " << it->c_str();
		}
*/
		cout << endl;
	}
}

int getkeys(const char *keyfile, vector<string>& keys) {
	char buf[1024];
	int ret = 0;
	keys.clear();
	FILE *fp = fopen(keyfile, "rt");
	if (fp) {
		while (!feof(fp)) {
			if (fgets(buf, sizeof(buf), fp)) {
				if (buf[strlen(buf) - 1] == 10)
					buf[strlen(buf) - 1] = 0;
				keys.push_back(buf);
			}
		}
		fclose(fp);
	} else {
		ret = 1;
		cout << "Can't open " << keyfile << endl;
	}
	return ret;
}

void usage() {
	cout << "Usage: getkeychanges server trace keyfile" << endl;
	exit(0);
}

int main(int argc, char *argv[]) {
	char *server = NULL;
	char *trace = NULL;
	char *keyfile = NULL;
	vector<string> keys;
	if (argc < 4)
		usage();
	server = argv[1];
	trace = argv[2];
	keyfile = argv[3];
	if (getkeys(keyfile, keys))
		return 1;
	getupdatestat2(server, trace, keys);
	return 0;
}

