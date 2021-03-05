// tracequery.h
#ifndef TRACEQUERY_H
#define TRACEQUERY_H

#include <string>
#include <vector>
#include <list>
#include <map>
#include <set>
#include "../libtracereplay/appstatestore.h"
#include "../../timetravelstore/timetravelstore/timetravelstore.h"

class TraceQuery {
public:
// data types
struct keyranking {
	//char key[512];
	int key;
	double ranking;
	double ratio;
	int versions;
};
enum RankPolicy {
	POLICY_BYUPDATE = 0,
	POLICY_BYRATIO = 1,
	POLICY_BYHYBRID = 2
};
enum {
	MAX_RATIO = 999999
};
enum TraversePolicy {
	BREADTH_FIRST = 0,
	DEPTH_FIRST = 1,
};

enum RollbackStrategy {
	ROLLBACK_NONE = 0,
	ROLLBACK_BYTIME = 1,
	ROLLBACK_BYHYBRID = 2,
};

	TraceQuery();
	~TraceQuery();
	int init(const char *server);
	void settrace(const char *tracename);
	int setclustering(const char *appname, double clustering, int windowsize = 1, int mode = 0);
	int getclusters(std::vector<std::vector<int> >& clusters);
	void menuapp(const char *appname);
	void listapps(std::vector<std::string>& apps);
	void listtraces(std::vector<std::string>& traces);
	int getaccessedversionedkeys(const char *appname, std::vector<std::string>& accessedkeys);
	int getaccessedkeys(const char *appname, std::vector<std::string>& accessedkeys);
	void listkeys(std::string appname, std::string name, std::vector<std::string> &keys);
	void calcrollbackcost(const char *appname, const char *key, std::vector<std::string>& keys, int time);
	void rankkeys(std::vector<int>& keys, std::list<keyranking>& rankedkeys, int time, RankPolicy policy, const char *key);
	int rollbackbyranking(const char *appname, const char *key, std::vector<int>& clusters, int time, RankPolicy policy);
	int get_key_version_num(const char *key);
	int rollbackcluster(int cluster, int time, int flag = 0, char *pdata = NULL, int *pdatalen = NULL, int *ptype = NULL, double *ptimestamp = NULL);
	int rollbackkey(const char *key, int time, int flag = 0, char *pdata = NULL, int *pdatalen = NULL, int *ptype = NULL, double *ptimestamp = NULL);
	int resetkey(const char *key);
	int get_current_version(const char *key);
	std::string time2str(int time);
	void testrollback(const char *appname, int id = 0, int days = 0, int writes = 1);
	void setinteractive(bool flag);
	void setthreshold(double threshold);
	int get_key_set_count(const char *key);
	int get_key_get_count(const char *key);
	int getappstat(const char *appname, int *numberaccess, int *numberupdate, int *numberdelete, double *starttime, double *endtime, std::set<std::string>& uniquekeys);
	double getratio(const char *key, int &num_versions);
	int enumkeys(const char *pattern, std::vector<std::string>& keys);
	void listkeyvalue(const char *key);
	double ** calckeydist(const char *appname, std::vector<std::string> &keys, int output = 1);
	void settraversepolicy(TraversePolicy policy);
	void setrollbackstrategy(int strategy);
	void settraversedepth(int traverse_depth);
	void settimebound(double time_bound);
	int set_key_value(const char *key, int version, const char *value, int valuelen, int type, double timestamp);
	int get_key_value(const char *key, int version, char *value, int *valuelen, int *type, double *timestamp);
	int get_key_timestamps(const char *key, double timestamp, std::list<double>& times, int check_dup = 1);
	void queryapp(const char *appname, int totalonly, int batch = 0);

	int m_costbytime;
	int m_costbyratio;
	int m_costbyhybrid;
	std::set<std::string> m_collateraldamage_bytime;
	std::list<std::list<std::string> > m_rollbackkeys;
	double getclustering();
	int getwindowsize();
	int getavgclustersize();
	int getkeycount();
	bool keyidincluster(int keyid, int cluster);

private:
	// methods
	std::string value2str(int type, char *value);
	int getlatestversion(const char *key, std::string &value);
	void calcintervaldist(TimeTravelStore::key_info_t &key_info, const char *key, double& avg, double& var, int& outliers, double& cv);
	double getlatestkeysettime(std::vector<std::string>& keys);
	void listkeyvalues(const char *appname, const char *name, std::vector<std::string> &keys);
	void removeconstkeys(std::vector<std::string> &keys);
	void insertkeyranking(std::list<keyranking>& updates, int key, double ranking, double ratio, int versions, int order);
	int rollbackbytime(const char *appname, const char *key, std::vector<int>& keys, int time);
	int aggregateaccess(const char *appname, std::set<std::string> &accessedkeys, std::set<std::string> &updatedkeys, std::set<std::string> &deletedkeys);
	int rollbackbyrankingex(const char *appname, const char *key, std::vector<int>& clusters, int time, RankPolicy policy);
	int gendistarray(std::vector<std::string>& keys, double **distmatrix, int output);
	int getdistkeypair(const std::string& key1, const std::string& key2, double earliestime, int &update1, int &update2);
	double getearliestkeysettime(std::vector<std::string>& keys);
	double getearliestkeygettime(std::vector<std::string>& keys);
	const char *id2key(int id) const;
	double getclusterratio(int cluster, int &num_versions);
	bool keyincluster(const char *key, int cluster);

// properties
	AppStateStore *appstore;
	TimeTravelStore *ttstore;
	char tracename[128];
	double totalexecutiontime;
	int totalaccess;
	int totalupdate;
	int totaldelete;
	double m_threshold;
	bool m_interactive;
	double m_clustering;
	int m_windowsize;
    std::vector<std::string> m_keys;
	std::vector<std::vector <int> > m_clusterslink;
	std::map<int, int> m_clustersrollbacks;
	int multiple_writes;
	TraversePolicy traverse_policy;
	int rollback_strategy;
	double m_time_bound; // time bound in number of days
	double m_latestkeysettime;
	int m_clusteringmode; // 0 - writes, 1 - reads
};

#endif

