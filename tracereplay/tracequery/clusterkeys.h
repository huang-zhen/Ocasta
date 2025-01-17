#ifndef CLUSTERKEYS_H
#define CLUSTERKEYS_H
#include <vector>
#include <string>

const int NO_LINK = 999999.0;

extern "C" {
int cluster(double **distmatrix, int nrows, std::vector<std::string> index, int nclusters, std::vector<std::vector <int> > & clusters, double threshold);
void dispclusters(std::vector<std::string> &index, std::vector<std::vector <int> > & clusters);
}

#endif

