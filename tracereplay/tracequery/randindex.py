#!/usr/bin/python
# rankindex
import sys, os

def readclusters(id, file):
	global clusters
	input = open(file, 'r')
	line_num = 0
	while input:
		line = input.readline()
		line_num = line_num + 1
		if not line:
			break
		line = line.strip()
		if not line:
			continue
		if line.find('#') == 0:
			continue
		parts = line.split(',')
		#print file, ':', line_num
		key = parts[0]
		cluster = parts[1]
		clusters[id][key] = cluster
	input.close()

def usage():
	print "Usage: rankindex clusters1 clusters2"
	exit()

if len(sys.argv) < 3:
	usage()
clusters = [{}, {}]
clusters1 = sys.argv[1]
clusters2 = sys.argv[2]

readclusters(0, clusters1)
readclusters(1, clusters2)
#print clusters[0]
#print clusters[1]
keys = []
for key in clusters[0]:
	if key in clusters[1]:
		keys.append(key)
if len(keys) == 0:
	print "No common keys"
	exit()
count1 = 0.0
count2 = 0.0
totcount = 0.0
for i, key1 in enumerate(keys):
	for j in range(i + 1, len(keys)):
		totcount = totcount + 1
		key2 = keys[j]
		if (clusters[0][key1] == clusters[0][key2]) and (clusters[1][key1] == clusters[1][key2]):
			count1 = count1 + 1
		if (clusters[0][key1] != clusters[0][key2]) and (clusters[1][key1] != clusters[1][key2]):
			count2 = count2 + 1
print clusters1, clusters2, len(keys), count1, count2, totcount, (count1 + count2)/totcount

		
