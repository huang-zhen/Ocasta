// clusterkeys.cpp
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <algorithm>
#include <limits>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
extern "C" {
#include "cluster.h"
};
#include "clusterkeys.h"

using namespace std;

struct pairdist {
	int key1;
	int update1;
	int key2;
	int update2;
	double value;
};

void remove_blanks(string &str)
{
	str.erase(remove_if(str.begin(), str.end(), ::isspace), str.end());
}

int parseline(char *line, string &key1, string &key2, pairdist &dist)
{
	int fields = 0;
	char *token = strtok(line, ",");
	while (token) {
		fields ++;
		switch (fields) {
		case 1:
			key1 = token;
			remove_blanks(key1);
			break;
		case 2:
			dist.update1 = atoi(token);
			break;
		case 3:
			key2 = token;
			remove_blanks(key2);
			break;
		case 4:
			dist.update2 = atoi(token);
			break;
		case 5:
			if (atof(token) > 0)
				dist.value = (dist.update1 + dist.update2) / 2 * atof(token);
			else
				dist.value = 0;
			break;
		}
		token = strtok(NULL, ",");
	}
	return (fields >= 3);
}

double **parsefile(const char *filename, int& nrows, vector<string>& index)
{
	int count = 0;
	double **distmatrix = NULL;
	char *buf;
	int bufsize = 16384;
	vector<pairdist> dists;
	map<string, int> keys;
	int keycount = 0;

	buf = new char[bufsize];
	if (!buf) {
		cerr << "Out of memory" << endl;
		return NULL;
	}
	FILE *fp = fopen(filename, "r");
	if (!fp) {
		cerr << "Unable to open " << filename << endl;
		return NULL;
	}
	while (!feof(fp)) {
		if (!fgets(buf, bufsize, fp))
			break;
		pairdist dist;
		string key1, key2;
		if (parseline(buf, key1, key2, dist)) {
			count ++;
			if (count % 10000 == 0)
				cerr << "parse line " << count << endl;
			if (keys.find(key1) == keys.end()) {
				keys[key1] = keycount;
				index.push_back(key1);
				keycount ++;
			}
			if (keys.find(key2) == keys.end()) {
				keys[key2] = keycount;
				index.push_back(key2);
				keycount ++;
			}
			dist.key1 = keys.find(key1)->second;
			dist.key2 = keys.find(key2)->second;
			dists.push_back(dist);
		}
	}
	fclose(fp);
	delete[] buf;
	keys.clear();
	nrows = keycount;
	distmatrix = (double **)malloc(keycount * sizeof(double*));
	if (!distmatrix) {
		cerr << "Out of memory" << endl;
		return NULL;
	}
	for (int i = 0; i < keycount; i++) {
		distmatrix[i] = (double *)calloc(keycount, sizeof(double));
		if (!distmatrix[i]) {
			cerr << "distmatrix[" << i << "]" << endl;
			cerr << "Out of memory" << endl;
			return NULL;
		}
	}
	for (vector<pairdist>::iterator it = dists.begin(); it != dists.end(); it++) {
		int nkey1 = it->key1;
		int nkey2 = it->key2;
		distmatrix[nkey1][nkey2] = it->value;
		distmatrix[nkey2][nkey1] = it->value;
	}
	for (int i = 0; i < keycount; i++)
		for (int j = 0; j < keycount; j++)
			if (distmatrix[i][j] == 0)
				distmatrix[i][j] = NO_LINK;
	return distmatrix;
}

int dfs(Node *tree, int node, int *traversed, int *clusterid, int clusters)
{
	if (traversed[node])
		return 0;
	traversed[node] = 1;
	if (tree[node].left >= 0) {
		clusterid[tree[node].left] = clusters;
	} else
		dfs(tree, -tree[node].left - 1, traversed, clusterid, clusters);
		
	if (tree[node].right >= 0) {
		clusterid[tree[node].right] = clusters;
	} else
		dfs(tree, -tree[node].right - 1, traversed, clusterid, clusters);
	return 1;
}

int getclusters(int nrows, Node *tree, int *clusterid, double threshold)
{
	int *traversed = NULL;
	int clusters = 0;

	traversed = (int *)calloc(nrows, sizeof(int));
	if (traversed == NULL) {
		cerr << "Out of memory" << endl;
		return 0;
	}
	for (int i = nrows - 2; i >= 0; i--) {
		if (tree[i].distance != NO_LINK && tree[i].distance <= 1/threshold)
			if (dfs(tree, i, traversed, clusterid, clusters))
				clusters ++;
	}
	for (int i = 0; i < nrows; i++) {
		if (clusterid[i] == -1)
			clusterid[i] = clusters++;
	}
	free(traversed);
	return clusters;
}

int cluster(double **distmatrix, int nrows, vector<string> index, int nclusters, vector<vector <int> > & clusters, double threshold)
{
	int nnodes = nrows - 1;
	Node *tree;
	int *clusterid;

	tree = treecluster(nrows, nrows, 0, 0, 0, 0, 'e', 'm', distmatrix);
	if (!tree) {
		cerr << "treecluster failed" << endl;
		return 0;
	}
  fprintf(stderr, "Node     Item 1   Item 2    Distance\n");
  for(int i=0; i<nnodes; i++)
    fprintf(stderr, "%3d:%9d%9d      %g\n",
           -i-1, tree[i].left, tree[i].right, tree[i].distance);
  fprintf(stderr, "\n");
  clusterid = (int *)malloc(nrows * sizeof(int));
  for (int i = 0; i < nrows; i++)
	clusterid[i] = -1;

  //printf("=============== Cutting a hierarchical clustering tree ==========\n");
  if (nclusters > 0)
	  cuttree (nrows, tree, nclusters, clusterid);
  else {
	  nclusters = getclusters(nrows, tree, clusterid, threshold);
      if (nclusters == 0)
		return 0;
  }

  //for(int i=0; i<nrows; i++)
   // printf("Gene %s: cluster %2d\n", index[i].c_str(), clusterid[i]);
  for (int i = 0; i < nclusters; i++) {
	//printf("============ cluster %d ===========\n", i);
	vector<int> cluster;
	int count = 0;
  	for(int j=0; j<nrows; j++)
		if (clusterid[j] == i) {
   			//printf("%d:%s\n", j, index[j].c_str());
			cluster.push_back(j);
			count++;
		}
    clusters.push_back(cluster);
	//printf("============ cluster %d (%d) ===========\n", i, count);
  	//printf("\n");
  }
  free(tree);
  free(clusterid);
  return nclusters;
}

extern "C" {
void dispclusters(vector<string> &index, vector<vector <int> > & clusters)
{
		int i = 0;
		for (vector<vector <int> >::iterator it = clusters.begin(); it != clusters.end(); it++) {
			fprintf(stderr, "==== cluster %d ====\n", i);
			for (vector<int>::iterator iit = it->begin(); iit != it->end(); iit++)
				fprintf(stderr, "%d:%s\n", *iit + 1, index[*iit].c_str());
			fprintf(stderr, "==== cluster %d (%ld) ====\n", i, it->size());	
			fprintf(stderr, "\n");
			i++;
		}
}
}

#ifdef STANDALONE
void usage()
{
	cout << "clusterkeys distfile [nclusters]" << endl;
	exit(1);
}

int main(int argc, char *argv[]) {
	char *filename = NULL;
	double **distmatrix = NULL;
	int nrows = 0;
	vector<string> index;
	int nclusters = 0;
	vector<vector <int> > clusters;

	if (argc < 2)
		usage();
	filename = argv[1];
	if (argc == 3)
		nclusters = atoi(argv[2]);
	distmatrix = parsefile(filename, nrows, index);
	if (distmatrix) {
		cluster(distmatrix, nrows, index, nclusters, clusters, 2.0);
		//dispclusters(index, clusters);
		free(distmatrix);
	}
	return 0;
}
#endif

