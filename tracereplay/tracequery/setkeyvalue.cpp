// setkeyvalue.c
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
	cout << "Usage: setkeyvalue server trace key version value valuelen type" << endl;
	exit(0);
}

// valuelen: 0 - get value only
//	     -1 - use string length of value
//	     >0 - specified length
int main(int argc, char *argv[]) {
	
	char *server = NULL;
	char *trace = NULL;
	char *key = NULL;
	char *value = NULL;
	int valuelen = 0;
	int count;
	char *oldvalue;
	int len;
	int type;
	double timestamp;
	int version;
	int err = 0;
	int oldvaluelen = 0;
	int oldtype = 0;
	double oldtimestamp;

	if (argc != 8)
		usage();

	server = argv[1];
	trace = argv[2];
	key = argv[3];
	version = atoi(argv[4]);
	value = argv[5];
	valuelen = atoi(argv[6]);
	type = atoi(argv[7]);

	tracequery.init(server);
	tracequery.settrace(trace);
	oldvalue = new char[TimeTravelStore::max_value_len];
	if (!oldvalue) {
		cerr << "Failed to allocate buf for old value" << endl;
		cout << endl;
		return 1;
	}
	if (tracequery.get_key_value(key, version, oldvalue, &oldvaluelen, &oldtype, &oldtimestamp)) {
		cerr << "Failed to get value for key " << key << endl;
		cout << endl;
		return 1;
	}
	if (type == -1)
		type = oldtype;
	if (valuelen == -1)
		valuelen = strlen(value) + 1;
	if (valuelen > 0) {
		if (tracequery.set_key_value(key, version, value, valuelen, type, oldtimestamp)) {
			cerr << "Failed to set value for key " << key << endl;
			cout << endl;
			return 1; 
		}
	}
	cout << oldvalue << ", " << oldvaluelen << ", " << oldtype << endl;
	return 0;
}

