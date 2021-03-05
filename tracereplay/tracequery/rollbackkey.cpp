// rollbackkey.c
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include "../libtracequery/tracequery.h"
#include "../../timetravelstore/timetravelstore/timetravelstore.h"
using namespace std;

TraceQuery tracequery;


// count: -1 reset current version
void usage() {
	cout << "Usage: rollbackkey server trace key count" << endl;
	exit(0);
}

int main(int argc, char *argv[]) {
	
	char *server;
	char *trace;
	char *key;
	int count;
	char *buf;
	int len;
	int type;
	double time;
	int old_current_version;
	int new_current_version;
	int err = 0;

	if (argc < 5)
		usage();

	server = argv[1];
	trace = argv[2];
	key = argv[3];
	count = atoi(argv[4]);

	tracequery.init(server);
	tracequery.settrace(trace);
	buf = new char[TimeTravelStore::max_value_len];
	if (!buf) {
		cerr << "Failed to allocate buf" << endl;
		return 1;
	}
	old_current_version = tracequery.get_current_version(key);
	if (count != -1) {
		if (!tracequery.rollbackkey(key, 0, 1, buf, &len, &type, &time))
			cout << buf << endl;
		else {
			cout << endl;
			err = 1;
			cerr << "Failed to roll back " << key << " for " << count << " times" << endl;
		}
	} else {
		if (tracequery.resetkey(key)) {
			err = 1;
			cerr << "Failed to reset " << key << endl;
		}
	}
	new_current_version = tracequery.get_current_version(key);
	//cerr << "current_version of " << key << ": " << old_current_version << "->" << new_current_version << endl;
	return 0;
}

