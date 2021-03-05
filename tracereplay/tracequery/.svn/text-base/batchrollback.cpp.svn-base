// batchrollback.cpp
// dump accessedversioned files for each application from each trace

#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <map>
#include "tracequery.h"
using namespace std;


struct stat {
	int min;
	int max;
	int avg;
};

int main(int argc, char* argv[])
{
	TraceQuery tracequery;

	char *server = "127.0.0.1";
	char *appname = NULL;
	server = argv[1];
	appname = argv[2];
	
	map<string, stat> keystat;

	tracequery.init(server);
	vector<string> traces;
	tracequery.listtraces(traces);
	for (int i = 3; i < argc; i++) {
		//cout << "Key " << argv[i] << endl;
		for (vector<string>::iterator it = traces.begin(); it != traces.end(); it++) {
			//cout << "Processing " << it->c_str() << endl;
			tracequery.settrace(it->c_str());
			vector<string> apps;
			tracequery.listapps(apps);

			for (vector<string>::iterator ait = apps.begin(); ait != apps.end(); ait++) {
			if (*ait == appname) {
				vector<string> keys;
				tracequery.getaccessedversionedkeys(ait->c_str(), keys);
					for (vector<string>::iterator it = keys.begin(); it != keys.end(); it++)
						if (*it == argv[i]) {
							//cout << "Calcrollbackcost" << endl;
							tracequery.calcrollbackcost(appname, keys[i - 1].c_str(), keys, 0);
						}
				}
			}
		}
	}
	return 0;
}

