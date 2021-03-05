// batchquery.cpp
// dump accessedversioned files for each application from each trace

#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include "tracequery.h"
using namespace std;

void processtrace(TraceQuery &tracequery, const char *trace)
{
	tracequery.settrace(trace);
	vector<string> apps;
	tracequery.listapps(apps);
	for (vector<string>::iterator ait = apps.begin(); ait != apps.end(); ait++) {
		vector<string> accessedkeys;
		tracequery.getaccessedversionedkeys(ait->c_str(), accessedkeys);
		tracequery.listkeys(ait->c_str(), "accessedversioned", accessedkeys);
	}
}

int main(int argc, char* argv[])
{
	TraceQuery tracequery;

	char *server = "127.0.0.1";

	if (argc > 1)
		server = argv[1];

	tracequery.init(server);
	vector<string> traces;
	tracequery.listtraces(traces);
	for (vector<string>::iterator it = traces.begin(); it != traces.end(); it++) {
		cerr << "Processing " << it->c_str() << endl;
		processtrace(tracequery, it->c_str());
	}
	if (traces.size() == 0) {
		if (argc > 2)	
			processtrace(tracequery, argv[2]);
		else {
			char buf[80];
			cout << "Can't find list of traces in the database" << endl;
			cout << "Please specifiy a batchquery tracename: ";
			cin >> buf;
			processtrace(tracequery, buf);
		}
	}
	return 0;
}
