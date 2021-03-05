#!/bin/bash
# randindex files
FILE=Explorer.EXE.clusters.can
echo $FILE
echo
randindex.py adam.$FILE afshar.$FILE
randindex.py adam.$FILE ben.$FILE
randindex.py adam.$FILE jack.$FILE
randindex.py ben.$FILE afshar.$FILE 
randindex.py ben.$FILE jack.$FILE
randindex.py jack.$FILE afshar.$FILE
FILE=WINWORD.EXE.clusters.can
echo $FILE
echo
randindex.py adam.$FILE ben.$FILE
randindex.py adam.$FILE jack.$FILE
randindex.py adam.$FILE lie.$FILE
randindex.py jack.$FILE ben.$FILE 
randindex.py jack.$FILE lie.$FILE
randindex.py lie.$FILE ben.$FILE
FILE=mspaint.exe.clusters.can
echo $FILE
echo
randindex.py afshar.$FILE jack.$FILE
FILE=wmplayer.exe.clusters.can
echo $FILE
echo
randindex.py afshar.$FILE ben.$FILE
randindex.py afshar.$FILE jack.$FILE
randindex.py ben.$FILE jack.$FILE

