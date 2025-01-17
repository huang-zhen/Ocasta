// main.cpp

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include "../libtracequery/tracequery.h"
#include "../../timetravelstore/timetravelstore/timetravelstore.h"

using namespace std;

TraceQuery tracequery;

int get_app_max_version(const char *appname)
{
	vector<string> keys;
	tracequery.getaccessedversionedkeys(appname, keys);
	int max_versions = 0;
	for (vector<string>::iterator it_keys = keys.begin(); it_keys != keys.end(); it_keys++) {
		int versions = tracequery.get_key_set_count(it_keys->c_str());
		if (versions > max_versions)
			max_versions = versions;
	}
	return max_versions;
}

struct AppVersion {
	string appname;
	int version;
};

bool compareAppVersion(const AppVersion &lhs, const AppVersion &rhs)
{
	return lhs.version > rhs.version;
}

void listapps(int users)
{
	vector<string> apps;
	tracequery.listapps(apps);

	static map<string, list<AppVersion> > appNames;

	cout << "List for " << users << " users" << endl;
	if (appNames.size() > 0)
		goto use_cache;

	for (vector<string>::iterator it = apps.begin(); it != apps.end(); it++)
{
		cout << "." << flush;
		// parse appname
		string appname;
		size_t pos = it->find('.');
		if (pos != string::npos) {
			string ext = it->substr(pos + 1);
			if (ext == "EXE" || ext == "exe") {
				appname = *it;
			} else {
				appname = ext;
			}
		} else {
			appname = *it;
		}
		AppVersion appVersion;
		appVersion.appname = *it;
		appVersion.version = get_app_max_version(it->c_str());
		appNames[appname].push_back(appVersion);
	}
	cout << endl;
use_cache:
	for (map<string, list<AppVersion> >::iterator it = appNames.begin(); it != appNames.end(); it++) {
		it->second.sort(compareAppVersion);
		cout << it->first.c_str() << ":" << endl;
		int i = 0;
		for (list<AppVersion>::iterator lit = it->second.begin(); lit != it->second.end(); lit++) {
			if (++i > users)
				break;
			cout << "\t" << i << ". " << lit->appname << ": " << lit->version << endl;
			
		}
	}
}

void output_rollbacks(const char *tracename, const char *appname, int keyid, int days, int writes, int bound)
{
	cout << "# trace: " << tracename << endl;
	cout << "# appname: " << appname << endl;
	cout << "# keyid: " << keyid << endl;
	cout << "# days: " << days << endl;
	cout << "# writes: " << writes << endl;
	cout << "# bound: " << bound << endl;
	cout << "# clustering: " << tracequery.getclustering() << endl;
	cout << "# window size: " << tracequery.getwindowsize() << endl;

	cout << "# rollbacks: " << tracequery.m_costbyhybrid << endl;
	cout << "# key count: " << tracequery.getkeycount() << endl;
	cout << "# avg cluster size: " << tracequery.getavgclustersize() << endl;
	int i = 1;
	for (list<list<string> >::iterator it = tracequery.m_rollbackkeys.begin(); it != tracequery.m_rollbackkeys.end(); it++, i++) {
		for (list<string>::iterator lit = it->begin(); lit != it->end(); lit++) {
			if (lit == it->begin()) {
				cout << '@' << *lit << i << ", ";
				lit++;
				cout << *lit << endl;
			} else
				cout << '\t' << *lit << endl;
		}
	}
}

int run_ex(int rollback_strategy, TraceQuery::TraversePolicy traverse_policy, const char *tracename, const char *appname, int keyid, int days, int writes, int bound)
{
	tracequery.setrollbackstrategy(rollback_strategy);
	tracequery.settraversepolicy(traverse_policy);
	if (bound == -1)
		tracequery.settimebound(days);
	else
		tracequery.settimebound(bound);
	tracequery.testrollback(appname, keyid, days, writes);

	output_rollbacks(tracename, appname, keyid, days, writes, bound);
	return tracequery.m_costbyhybrid;
}

// time_bound: -1 - set time_bound optimisticly
void runhybrid(const char *tracename, const char *appname, int keyid, int days[], int day_count, int costbyhybrid[], int writes, int time_bound, int day_collateraldamage, set<string>& collateraldamage_bytime)
{
	tracequery.setrollbackstrategy(TraceQuery::ROLLBACK_BYHYBRID);
	if (time_bound != -1)
		tracequery.settimebound(time_bound);

	tracequery.settraversepolicy(TraceQuery::BREADTH_FIRST);
	for (int i = 0; i < day_count; i++) {
		if (time_bound == -1)
			tracequery.settimebound(days[i]);
		tracequery.testrollback(appname, keyid, days[i], writes);
		costbyhybrid[i] = tracequery.m_costbyhybrid;
	}

	cout << writes << ", " << time_bound << ", " << "BFS, ";
	for (int i = 0; i < day_count; i++) {
		if (i == 0)
			cout << costbyhybrid[i];
		else
			cout << ", " << costbyhybrid[i];
	}
	cout << endl;

	tracequery.settraversepolicy(TraceQuery::DEPTH_FIRST);
	for (int i = 0; i < day_count; i++) {
		if (time_bound == -1)
			tracequery.settimebound(days[i]);
		tracequery.testrollback(appname, keyid, days[i], writes);
		costbyhybrid[i] = tracequery.m_costbyhybrid;
		if (days[i] == day_collateraldamage) {
			collateraldamage_bytime = tracequery.m_collateraldamage_bytime;
		}
	}
	cout << writes << ", " << time_bound << ", " << "DFS, ";
	for (int i = 0; i < day_count; i++) {
		if (i == 0)
			cout << costbyhybrid[i];
		else
			cout << ", " << costbyhybrid[i];
	}
	cout << endl;
}

int batchmode_ex(const char *tracename, const char *appname, int keyid, int writes, double clustering, double threshold)
{
	int days[] = {1, 3, 7, 14};
	int bounds[] = {5, 15, 25, 35, 45, 55, 65, 75};
	int costbytime[4];
	int collateraldamage[4];
	int costbyratio;
	//double thresholds[] = {0, 0.05, 0.01};
	//double thresholds[] = {0, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5};
	double thresholds[] = {0};
	int *costbyhybrid = NULL;
	int daycount = sizeof(days)/sizeof(days[0]);

	tracequery.setrollbackstrategy(TraceQuery::ROLLBACK_BYTIME);
	costbyratio = 0;
	for (int i = 0; i < daycount; i++) {
		costbytime[i] = 0;
	}
	costbyhybrid = new int[daycount];
	if (costbyhybrid == NULL) {
		cerr << "Out of memory in " << __FUNCTION__ << endl;
		return -1;
	}
	for (int i = 0; i < sizeof(thresholds)/sizeof(thresholds[0]); i++) {
		costbyhybrid[i] = 0;
	}

	cout << "# trace: " << tracename << endl;
	cout << "# application: " << appname << endl;
	cout << "# keyid: " << keyid << endl;
	cout << "# writes: " << writes << endl;
	cout << "# clustering: " << clustering << endl;
	cout << "# window size: " << tracequery.getwindowsize() << endl;
	cout << "# threshold: " << threshold << endl;
	cout << endl;

	cout << "# " << tracename << ", " << appname << ", " << keyid;

	tracequery.setthreshold(threshold);
	for (int i = 0; i < daycount; i++) {
		tracequery.testrollback(appname, keyid, days[i], writes);
		costbyratio = tracequery.m_costbyratio + 1;
		costbytime[i] = tracequery.m_costbytime + 1;
		collateraldamage[i] = tracequery.m_collateraldamage_bytime.size();
	}

/*
	for (int i = 0; i < sizeof(thresholds)/sizeof(thresholds[0]); i++) {
		tracequery.setthreshold(thresholds[i]);
		tracequery.testrollback(appname, keyid, 0);
		costbyhybrid[i] = tracequery.m_costbyhybrid + 1;
	}
*/
	int versions = 0;
	vector<string> keys;
	tracequery.getaccessedversionedkeys(appname, keys);
	double ratio = tracequery.getratio(keys[keyid - 1].c_str(), versions);
	cout << ", " << ratio << ", " << versions; 
	for (int i = 0; i < daycount; i++) {
		cout << ", ";
		cout << costbytime[i];
	}
	cout << ", " << costbyratio;

	for (int i = 0; i < daycount; i++) {
		cout << ", ";
		cout << collateraldamage[i];
	}

	cout << endl;

/*
	int minhybrid = 99999;
	int maxhybrid = 0.0;
	for (int i = 0; i < sizeof(thresholds)/sizeof(thresholds[0]); i++) {
		if (costbyhybrid[i] < minhybrid)
			minhybrid = costbyhybrid[i];	
		if (costbyhybrid[i] > maxhybrid)
			maxhybrid = costbyhybrid[i];
	}

	for (int i = 0; i < sizeof(thresholds)/sizeof(thresholds[0]); i++) {
		//cout << ", " << costbyhybrid[i];
		//cout << thresholds[i] << ", " << (maxhybrid - costbyhybrid[i])/(maxhybrid - minhybrid) << ", " <<  costbyhybrid[i] << endl;
		cout << thresholds[i] << ", " << (maxhybrid - costbyhybrid[i]) << ", " <<  costbyhybrid[i] << endl;
	}
*/
	cout << "# Days: ";

	for (int i = 0; i < daycount; i++)
		if (i == 0)
			cout << days[i];
		else
			cout << ", " << days[i];
	cout << endl;
	cout << "# writes, bound, strategy, cost1, cost2, ..." << endl;

	set<string> keys_collateraldamage_bytime;

	for (int i = 1; i <= writes; i++)
		runhybrid(tracename, appname, keyid, days, daycount, costbyhybrid, i, -1, 3, keys_collateraldamage_bytime);
	cout << endl;

	cout << "# Days: " << days[1] << endl;
	cout << "# writes, bound, strategy, cost" << endl;
	for (int i = 0; i < sizeof(bounds)/sizeof(bounds[0]); i++)
		runhybrid(tracename, appname, keyid, &days[1], 1, costbyhybrid, 3, bounds[i], 0, keys_collateraldamage_bytime);

	cout << endl;

	cout << "# Collateral Damages by Snapshot Rollback: " << keys_collateraldamage_bytime.size() << endl << endl;
	for (set<string>::iterator it = keys_collateraldamage_bytime.begin(); it != keys_collateraldamage_bytime.end(); it++)
		cout << '\t' << *it << endl;

	delete[] costbyhybrid;
	return 0;
}

int batchmode2(const char *tracename, const char *appname, int keyid, int writes, double threshold, double clustering, int window_size, int days, int bound, int strategy)
{
	return 0;
}

int batchmode(const char *tracename, const char *appname, int keyid, int writes, double threshold, double clustering, int window_size, int days, int bound, int strategy)
{
	tracequery.settrace(tracename);
	if (tracequery.setclustering(appname, clustering, window_size) <= 0) {
		cerr << "setclustering failed" << endl;
		return -1;
	}
	if (strategy == 0) {
		// automated batch
		cerr << "# mode: batch" << endl;
		cerr << "# trace: " << tracename << endl;
		cerr << "# application: " << appname << endl;
		cerr << "# keyid: " << keyid << endl;
		cerr << "# writes: " << writes << endl;
		cerr << "# clustering: " << clustering << endl;
		cerr << "# days: " << days << endl;
		cerr << "# bound: " << bound << endl;
		cerr << "# strategy: " << strategy << endl;
		cerr << endl;

		if (keyid > 0)
			batchmode_ex(tracename, appname, keyid, writes, clustering, threshold);
		else {
			ofstream plotfile;
			char filename[80];

			sprintf(filename, "%s.%s.plot", tracename, appname);
			plotfile.open(filename);
			plotfile << "set term postscript eps blacktext \"Helvetica\" 24" << endl;
			plotfile << "set output 'rollbacks.eps'" << endl;
			plotfile << "set xlabel 'Thresholds'" << endl;
			plotfile << "set ylabel 'Reduction of rollbacks'" << endl;
			plotfile << "set logscale x" << endl;
			plotfile << "plot ";

			for (int i = 1; i <= -keyid; i++)
	{
	/*			output data points for only config keys in afshar's trace
	 *			should not hard-code them here!!!

				int points[] = {1, 105, 120, 2, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 46, 58, 59, 70, 73, 76, 86, 95};
				int hit = 0;
				for (int j = 0; j < sizeof(points)/sizeof(points[0]); j++)
					if (i == points[j])
						hit = 1;
				if (!hit)
					continue;
	*/
				streambuf *backup;
				ofstream datafile;

				char filename[80];
				sprintf(filename, "%s.%s.%d", tracename, appname, i);
				datafile.open(filename);
				backup = cout.rdbuf();
				cout.rdbuf(datafile.rdbuf());	
				batchmode_ex(tracename, appname, i, writes, clustering, threshold);
				cout.rdbuf(backup);
				datafile.close();
				if (i == 1)
					plotfile << " '" << filename << "'" << " using 1:2 title " << "'" << i << "'" << " with lines linecolor " << i;
				else
					plotfile << ", '" << filename << "'" << " using 1:2 title " << "'" << i << "'" << " with lines linecolor " << i;
			}
			plotfile << endl;
			plotfile.close();
		}
	} else {
		// manual batch
		tracequery.setthreshold(threshold);
		switch (strategy) {
		case 2:
			run_ex(TraceQuery::POLICY_BYHYBRID, TraceQuery::BREADTH_FIRST, tracename, appname, keyid, days, writes, bound);
			break;
		case 3:
			run_ex(TraceQuery::POLICY_BYHYBRID, TraceQuery::DEPTH_FIRST, tracename, appname, keyid, days, writes, bound);
			break;
		}
	}
	return 0;
}

void queryapp()
{
	char appname[80];

	do {
		cout << "Enter appname (* for all, 0 for exit, -1 for list): ";
		cin >> appname;
		if (strcmp(appname, "0") == 0) {
			break;
		} else if (strcmp(appname, "-1") == 0) {
			char buf[80];
			cout << "How many users to list for each application? ";
			cin >> buf;
			int users = atoi(buf);
			if (users == 0) {
				cout << "Invalid number of users!" << endl;
				break;
			}
			listapps(users);
		} else
			tracequery.menuapp(appname);
	} while (1);
}

void queryuser()
{
	do {
		char user[80];
		vector<string> apps;
		int totalaccess, totalupdate, totaldelete;
		double starttime, endtime;
		int count = 0;
		set<string> uniquekeys;

		cout << "Enter user name (* for all, 0 to exit): ";
		cin >> user;
		if (strcmp(user, "0") == 0)
			break;

		totalaccess = totalupdate = totaldelete = 0;
		starttime = (double)time(NULL);
		endtime = 0;
		tracequery.listapps(apps);

		for (vector<string>::iterator it = apps.begin(); it != apps.end(); it++)
	{
			if (strcmp(user, "*") == 0 || it->find(user) == 0) {
				int numberaccess, numberupdate, numberdelete;
				double appstarttime, appendtime;
				int keycount;
				set<string> appuniquekeys;
			
				count ++;
				tracequery.getappstat(it->c_str(), &numberaccess, &numberupdate, &numberdelete, &appstarttime, &appendtime, appuniquekeys);
				if (numberaccess > 0)
					totalaccess += numberaccess;
				if (numberupdate > 0)
					totalupdate += numberupdate;
				if (numberdelete > 0)
					totaldelete += numberdelete;
				if (appstarttime < starttime)
					starttime = appstarttime;
				if (appendtime > endtime)
					endtime = appendtime;
				if (appendtime < appstarttime)
					appendtime = appstarttime;

				cout << it->c_str() << ", " << numberaccess << ", " << numberupdate <<", " << numberdelete << ", " << appuniquekeys.size() << ", " << (appendtime - appstarttime)/24/60/60 << endl;
				uniquekeys.insert(appuniquekeys.begin(), appuniquekeys.end());
			}
		}
		if (count > 0) {
			int days = 0;
			if (endtime > starttime)
				days = (endtime - starttime)/24/60/60;
			cout << user << ", " << totalaccess << ", " << totalupdate << ", " << totaldelete << ", " << uniquekeys.size() << ", " << days << endl;
		} else
			cout << "No application found for " << user << "!"<< endl;
	} while (1);
}

void querykey()
{
	char pattern[TimeTravelStore::max_key_len + 1];
	vector<string> keys;

	while(1) {
		keys.clear();
		cout << "Enter key pattern (0 to exit): ";
		cin >> pattern;
		if (strcmp(pattern, "0") == 0)
			break;
		tracequery.enumkeys(pattern, keys);

		vector<pair<int, string> > sortedkeys;
		for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++) {
			int get_count = tracequery.get_key_get_count(it->c_str());
			sortedkeys.push_back(make_pair(get_count, *it));
		}
		sort(sortedkeys.begin(), sortedkeys.end());
		int i = 0;
		for (vector<pair<int, string> >::iterator it = sortedkeys.begin(); it != sortedkeys.end(); it++) {
			cout << ++i << ". " << it->second.c_str() << ", " << it->first << endl;
		}
		while (sortedkeys.size() > 0) {
			cout << "Choose a key " << "(" << 1 << " to " << i << ", 0 to exit): ";
			char buf[80];
			cin >> buf;
			int choice = atoi(buf);
			if (choice == 0)
				break;
			if (choice > sortedkeys.size())
				cout << "Invalid choice!" << endl;
			else
				tracequery.listkeyvalue(sortedkeys[choice - 1].second.c_str());
		}
	}
}

int statmode(const char *tracename)
{
	tracequery.settrace(tracename);
	vector<string> keys;
	cerr << "Getting list of keys..." << endl;
	tracequery.enumkeys("*", keys);
	int size = keys.size();
	int count = 0;
	for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++) {
		int num_versions = 0;
		const char *key = it->c_str();
		double ratio = tracequery.getratio(key, num_versions);
		if (ratio != -1 && ratio != TraceQuery::MAX_RATIO)
			cout << tracename << ", " << ratio << ", " << num_versions << ", " << key << endl;
		cerr << "." << flush;
		count ++;
		if (count % 5000 == 0)
			cerr << count/size << "% done" << endl;
	}
	cerr << endl;
	return 0;
}

int distmode2(const char *tracename, const char *appname, vector<int> keys)
{
	vector<string> apps;
	double thresholds[] = {0.1, 0.2, 0.5, 1, 2};
	//double thresholds[] = {1, 2};
	//int window_sizes[] = {20, 10, 5, 2, 1};
	int window_sizes[] = {1, 30, 60, 300, 600};

	tracequery.settrace(tracename);
	for (int w = 0; w < sizeof(window_sizes)/sizeof(window_sizes[0]); w++) {
		for (int t = 0; t < sizeof(thresholds)/sizeof(thresholds[0]); t++) {
			vector<vector<int> > clusters;
			tracequery.setclustering(appname, thresholds[t], window_sizes[w]);
			if (tracequery.getclusters(clusters) <= 0) {
				cerr << "setclustering failed" << endl;
				return -1;
			}
			int allinclude = 0;
			int keycount = 0;
			int largestclustersize = 0;
			for (vector<vector<int> >::iterator clustert = clusters.begin(); clustert != clusters.end(); clustert++) {
				keycount += clustert->size();
				if (clustert->size() > largestclustersize)
					largestclustersize = clustert->size();
			}
			for (vector<vector<int> >::iterator clustert = clusters.begin(); clustert != clusters.end(); clustert++) {
				vector<int> v(keys.size());
				vector<int>::iterator it;
				//cout << "*****" << endl;
				//for (vector<int>::iterator iit = clustert->begin(); iit != clustert->end(); iit++)
				//	cout << *iit << endl;
				sort(keys.begin(), keys.end());
				sort(clustert->begin(), clustert->end());
				it = set_intersection(keys.begin(), keys.end(), clustert->begin(), clustert->end(), v.begin());
				v.resize(it - v.begin());

				if (v.size() > 0) {
					if (find(v.begin(), v.end(), keys[0]) != v.end()) {
					 	if (v.size() < keys.size())
							allinclude = v.size() - keys.size();
						else {
							if (clustert->size() == keys.size())
								allinclude = 0;
							else
								allinclude = clustert->size() - keys.size();
						}
						break;
					}
				}					
			}
			if (t == 0)
				cout << allinclude << ',' << keycount/clusters.size() << ',' << largestclustersize << ',' << keycount;
			else
				cout << ',' << allinclude << ',' << keycount/clusters.size() << ',' << largestclustersize << ',' << keycount;
		}
		cout << endl;
	}
	return 0;
}

int distmode(const char *tracename, const char *appname, int reads)
{
	vector<string> apps;
	map<int, list<int> > clusters;

	int num_clusters = 0;

	tracequery.settrace(tracename);

	vector<string> keys;
	if (!reads)
		tracequery.getaccessedversionedkeys(appname, keys);
	else
		tracequery.getaccessedkeys(appname, keys);

	num_clusters = tracequery.setclustering(appname, 2, 1, reads);
	if (num_clusters <= 0) {
		cerr << "setclustering failed" << endl;
		return -1;
	}
	cerr << "# mode: clustering" << endl;
	cerr << "# trace: " << tracename << endl;
	cerr << "# application: " << appname << endl;
	cerr << "# total clusters: " << num_clusters << endl;
	cerr << "# total keys: " << keys.size() << endl;
	cerr << endl;

	cout << "# mode: clustering" << endl;
	cout << "# trace: " << tracename << endl;
	cout << "# application: " << appname << endl;
	cout << "# total clusters: " << num_clusters << endl;
	cout << "# total keys: " << keys.size() << endl;
	cout << endl;

	for (int i = 0; i < keys.size(); i++) {
		int cluster = -1;
		for (int c = 0; c < num_clusters; c++) {
			if (tracequery.keyidincluster(i, c)) {
				cluster = c;
				break;
			}
		}
		assert(cluster >= 0);
		//cout << keys[i] << "," << cluster << endl;
		if (clusters.find(cluster) == clusters.end()) {
			list<int> keys;
			keys.push_back(i);
			clusters[cluster] = keys;
		} else
			clusters[cluster].push_back(i);
	}
	for (map<int, list<int> >::iterator it = clusters.begin(); it != clusters.end(); it ++) {
		for (list<int>::iterator iit = it->second.begin(); iit != it->second.end(); iit++)
			cout << keys[*iit] << ',' << it->first << endl;
	}

/*	
	tracequery.listapps(apps);

	for (vector<string>::iterator it = apps.begin(); it != apps.end(); it++) {
		if (it->find(appname) != string::npos) {
			vector<string> keys;
			tracequery.getaccessedversionedkeys(it->c_str(), keys);

			tracequery.calckeydist(it->c_str(), keys);
		}
	}
*/
	return 0;
}

int distmode_ex(const char *tracename, const char *appname, int reads, double clustering, int windowsize)
{
	vector<string> apps;
	map<int, list<int> > clusters;

	int num_clusters = 0;
	char outfilename[256];

	sprintf(outfilename, "%s.%s.%d.%.2f.%d.clustering", tracename, appname, reads, clustering, windowsize);
	ofstream outfile(outfilename);

	tracequery.settrace(tracename);

	vector<string> keys;
	if (!reads)
		tracequery.getaccessedversionedkeys(appname, keys);
	else
		tracequery.getaccessedkeys(appname, keys);

	num_clusters = tracequery.setclustering(appname, clustering, windowsize, reads);
	if (num_clusters <= 0) {
		cerr << "setclustering failed" << endl;
		return -1;
	}
	cerr << "# mode: clustering" << endl;
	cerr << "# trace: " << tracename << endl;
	cerr << "# application: " << appname << endl;
	cerr << "# on reads: " << reads << endl;
	cerr << "# clustering: " << clustering << endl;
	cerr << "# window size: " << windowsize << endl;
	cerr << "# total clusters: " << num_clusters << endl;
	cerr << "# total keys: " << keys.size() << endl;
	cerr << endl;

	outfile << "# mode: clustering" << endl;
	outfile << "# trace: " << tracename << endl;
	outfile << "# application: " << appname << endl;
	outfile << "# on reads: " << reads << endl;
	outfile << "# clustering: " << clustering << endl;
	outfile << "# window size: " << windowsize << endl;
	outfile << "# total clusters: " << num_clusters << endl;
	outfile << "# total keys: " << keys.size() << endl;
	outfile << endl;

	for (int i = 0; i < keys.size(); i++) {
		int cluster = -1;
		for (int c = 0; c < num_clusters; c++) {
			if (tracequery.keyidincluster(i, c)) {
				cluster = c;
				break;
			}
		}
		assert(cluster >= 0);
		//cout << keys[i] << "," << cluster << endl;
		if (clusters.find(cluster) == clusters.end()) {
			list<int> keys;
			keys.push_back(i);
			clusters[cluster] = keys;
		} else
			clusters[cluster].push_back(i);
	}
	for (map<int, list<int> >::iterator it = clusters.begin(); it != clusters.end(); it ++) {
		for (list<int>::iterator iit = it->second.begin(); iit != it->second.end(); iit++)
			outfile << keys[*iit] << ',' << it->first << endl;
	}

/*	
	tracequery.listapps(apps);


	for (vector<string>::iterator it = apps.begin(); it != apps.end(); it++) {
		if (it->find(appname) != string::npos) {
			vector<string> keys;

			tracequery.getaccessedversionedkeys(it->c_str(), keys);

			tracequery.calckeydist(it->c_str(), keys);
		}
	}

*/
	outfile.close();
	return 0;
}

int appmode(const char *tracename)
{
	vector<string> apps;

	tracequery.settrace(tracename);
	tracequery.listapps(apps);

	for (vector<string>::iterator it = apps.begin(); it != apps.end(); it++) {
		tracequery.queryapp(it->c_str(), 0, 1);
	}
	//tracequery.queryapp("OUTLOOK.EXE", 0, 1);
	return 0;
}

void usage()
{
	cout << "Usage: tracequery [-b|-c|-s|-d|-a|-r] [server]" << endl;
	cout << "\t -b server tracename appname keyid writes threshold clustering days bound strategy" << endl;
	cout << "\t\t generate data for trials" << endl;
	cout << "\t -c server tracename appname keyid writes threshold clustering days bound strategy" << endl;
	cout << "\t\t calculate rollback cost" << endl;
	cout << "\t -s server tracename" << endl;
	cout << "\t\t list all the keys" << endl;
	cout << "\t -d server tracename appname key1 key2 ..." << endl;
	cout << "\t\t compute clustering" << endl;
	cout << "\t -r server tracename appname key1 key2 ..." << endl;
	cout << "\t\t compute clustering for reads" << endl;
	cout << "\t -g server tracename appname reads clustering windowsize" << endl;
	cout << "\t\t compute clustering for reads/writes with specified clustering and windowsize" << endl;
	cout << "\t -a server tracename" << endl;
	cout << "\t\t list keys accessed by each application" << endl;
	cout << "\t -? usage" << endl;
	cout << endl;
	exit(0);
}

int main(int argc, char* argv[])
{
	const char *server = "127.0.0.1";
	// mode: 1 -- b
	//       2 -- s
	//       3 -- d
	//       4 -- a
	//       5 -- c
	//	 6 -- r
	//	 7 -- g
	int mode = 0;
	int argstart = 1;

	cerr << "#";
	for (int i = 0; i < argc; i++)
		cerr << " " << argv[i];
	cerr << endl;

	if (argc > 1) {
		if (strcmp(argv[1], "-?") == 0) {
			usage();
		} else if (strcmp(argv[1], "-b") == 0) {
			if (argc < 9)
				usage();
			mode = 1;
			argstart ++;
		} else if (strcmp(argv[1], "-c") == 0) {
			if (argc < 9)
				usage();
			mode = 5;
			argstart ++;
		} else if (strcmp(argv[1], "-s") == 0) {
			mode = 2;
			if (argc != 4)
				usage();
			argstart ++;
		} else if (strcmp(argv[1], "-a") == 0) {
			mode = 4;
			if (argc != 4)
				usage();
			argstart ++;
		} else if (strcmp(argv[1], "-d") == 0) {
			mode = 3;
			if (argc < 5)
				usage();
			argstart++;
		} else if (strcmp(argv[1], "-r") == 0) {
			mode = 6;
			if (argc < 5)
				usage();
			argstart++;
		} else if (strcmp(argv[1], "-g") == 0) {
			mode = 7;
			if (argc < 7)
				usage();
			argstart++;
		}
		server = argv[argstart++];
	}

	//strcpy(tracename, "test");

	if (tracequery.init(server)) {
		cout << "Error initializing server" << endl;
		return 0;
	}
	tracequery.setinteractive(mode == 0);
	if (mode == 1) {
		char *tracename = argv[argstart++];
		char *appname = argv[argstart++];
		int keyid = atoi(argv[argstart++]);
		int writes = atoi(argv[argstart++]);
		double threshold = atof(argv[argstart++]);
		double clustering = atof(argv[argstart++]);
		int windowsize = atoi(argv[argstart++]);

		int days = 0;
		int bound = 0;
		int strategy = 0;
		if (argc >= 12) {
			days = atoi(argv[argstart++]);
			bound = atoi(argv[argstart++]);
			strategy = atoi(argv[argstart++]);
		}
		return batchmode(tracename, appname, keyid, writes, threshold, clustering, windowsize, days, bound, strategy);
	} else if (mode == 5) {
		char *tracename = argv[argstart++];
		char *appname = argv[argstart++];
		int keyid = atoi(argv[argstart++]);
		int writes = atoi(argv[argstart++]);
		double threshold = atof(argv[argstart++]);
		double clustering = atof(argv[argstart++]);
		int days = 0;
		int bound = 0;
		int strategy = 0;
		if (argc == 12) {
			days = atoi(argv[argstart++]);
			bound = atoi(argv[argstart++]);
			strategy = atoi(argv[argstart++]);
		}
		return batchmode2(tracename, appname, keyid, writes, threshold, clustering, 1, days, bound, strategy);
	} else if (mode == 2) {
		char *tracename = argv[argstart++];
		return statmode(tracename);
	} else if (mode == 4) {
		char *tracename = argv[argstart++];
		return appmode(tracename);
	} else if (mode == 3) {
		char *tracename = argv[argstart++];
		char *appname = argv[argstart++];
		vector<int> keys;
		for (int c = argstart; c < argc; c++)
			keys.push_back(atoi(argv[c]) - 1);
		if (keys.size() > 0)
			return distmode2(tracename, appname, keys);
		else
			return distmode(tracename, appname, 0);
	} else if (mode == 6) {
		char *tracename = argv[argstart++];
		char *appname = argv[argstart++];
		vector<int> keys;
		for (int c = argstart; c < argc; c++)
			keys.push_back(atoi(argv[c]) - 1);
		if (keys.size() > 0)
			return distmode2(tracename, appname, keys);
		else
			return distmode(tracename, appname, 1);
	} else if (mode == 7) {
		char *tracename = argv[argstart++];
		char *appname = argv[argstart++];
		int reads = atoi(argv[argstart++]);
		double clustering = atof(argv[argstart++]);
		int windowsize = atoi(argv[argstart++]);
		return distmode_ex(tracename, appname, reads, clustering, windowsize);
	}
	// mode == 0
	vector<string> traces;
	tracequery.listtraces(traces);
	bool exit = false;
	while (!exit) {
		char tracename[80];
		if (traces.size() == 0) {
			cout << "Enter trace name (0 to exit): ";
			cin >> tracename;
			if (strcmp(tracename, "0") == 0)
				exit = true;
		} else if (traces.size() == 1) {
			strncpy(tracename, traces[0].c_str(), sizeof(tracename));
			cout << "Use trace " << tracename << endl;
		} else {
			char buf[80];
			for (int i = 0; i < traces.size(); i++)
				cout << i << ". " << traces[i] << endl;
			while(1) {
				cout << "Select a trace (0 for exit, -1 for list): ";
				cin >> buf;
				int trace = atoi(buf);
				if (trace == 0) {
					exit = true;
					break;
				} else if (trace < 0 || trace > traces.size()) {
					cout << "Invalid choice!" << endl;
				} else {
					strncpy(tracename, traces[trace].c_str(), sizeof(tracename));
					break;
				}
			}
		}
		if (exit)
			break;
		tracequery.settrace(tracename);
		bool done = false;
		while(!done) {
			char buf[80];
			cout << "1. Query application" << endl;
			cout << "2. Query user" << endl;
			cout << "3. Query key" << endl;
			if (traces.size() > 1)
				cout << "4. Change trace" << endl;
			cout << "Enter your choice (0 to exit): ";
			cin >> buf;
			int choice = atoi(buf);
			switch(choice) {
				case 0:
					done = true;
					if (traces.size() == 1)
						exit = true;
					break;
				case 1:
					queryapp();
					break;
				case 2:
					queryuser();
					break;
				case 3:
					querykey();
					break;
				case 4:
					if (traces.size() > 1) {
						done = true;
						break;
					}
				default:
					cout << "Invalid choice!" << endl;
					break;
			}
		}
	}
	return 0;
}
