// tracequery.h
#ifndef TRACEQUERY_H
#define TRACEQUERY_H

#include <string>
#include <vector>
#include <list>
#include <map>
#include "../libtracereplay/appstatestore.h"
#include "../../timetravelstore/timetravelstore/timetravelstore.h"

class TraceQuery {
public:
	TraceQuery();
	~TraceQuery();
	int init(const char *server);
	void settrace(const char *tracename);
	void menuapp(const char *appname);
	void listapps(std::vector<std::string>& apps);
	void listtraces(std::vector<std::string>& traces);
	int getaccessedversionedkeys(const char *appname, std::vector<std::string>& accessedkeys);
	void listkeys(std::string appname, std::string name, std::vector<std::string> &keys);
	void calcrollbackcost(const char *appname, const char *key, std::vector<std::string>& keys, int time);

// data types
struct keyranking {
	char key[512];
	double ranking;
};
private:
// data
static const int max_ratio;
// methods
std::string time2str(int time);
std::string value2str(int type, char *value);
int getlatestversion(const char *key, std::string &value);
double getratio(const char *key, double time, int &num_versions);
void calcintervaldist(TimeTravelStore::key_info_t &key_info, const char *key, double& avg, double& var, int& outliers, double& cv);
int getlatestkeysettime(std::vector<std::string>& keys);

void listkeyvalues(std::string appname, std::string name, std::vector<std::string> &keys);
void queryapp(const char *appname, int totalonly);
int get_key_version_num(const char *key);
void rankkeys(std::vector<std::string>& keys, std::list<keyranking>& rankedkeys, int time, double threshold);
void removeconstkeys(std::vector<std::string>& keys);
int rollbackkey(const char *key, int time);
void insertkeyranking(std::list<keyranking>& updates, const char *key, double ranking, int order);
int rollbackbytime(const char *appname, const char *key, std::vector<std::string>& keys, int time);
int rollbackbyranking(const char *appname, const char *key, std::vector<std::string>& keys, int time, double threshold);

void testrollback(const char *appname);

// properties
	AppStateStore *appstore;
	TimeTravelStore *ttstore;
	char tracename[128];
};

#endif

