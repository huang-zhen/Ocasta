#include <iostream>
#include <algorithm>
#include "../libtracequery/tracequery.h"
#include "../../timetravelstore/timetravelstore/timetravelstore.h"

using namespace std;

TraceQuery tracequery;

void usage() {
	cout << "Usage: getkeytimestamps server trace key" << endl;
	exit(0);
}

int main(int argc, char *argv[]) {
	char *server, *tracename, *key;

	if (argc != 4)
		usage();
	server = argv[1];
	tracename = argv[2];
	key = argv[3];
	if (tracequery.init(server)) {
		cout << "Error initializing server" << endl;
		return 0;
	}
	tracequery.settrace(tracename);
	list<double> times;
	tracequery.get_key_timestamps(key, 0, times);
	cout << key << endl;
	for (list<double>::iterator it = times.begin(); it != times.end(); it++)
		cout << '\t' << tracequery.time2str(*it) << endl;
	return 0;
}

