// tracereplay.cpp : Replay traces collected by TraceAPI tool
//
#include <iostream>

#ifdef WIN32
#include "stdafx.h"
#else
#include <stdlib.h>
#endif
#include "replay.h"
using namespace std;

void usage()
{
	cerr << "Usage: tracereplay tracename tracefile" << endl;
	exit(1);
}

int main(int argc, char* argv[])
{
	const char* filename = NULL;
	const char* tracename = NULL;

	if (argc < 3)
		usage();
	tracename = argv[1];
	filename = argv[2];
	Replayer replayer;
	replayer.replayfile(tracename, filename);
	return 0;
}
