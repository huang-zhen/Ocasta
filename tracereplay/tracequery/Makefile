all: tracequery clusterkeys clusterlib.a rollbackkey setkeyvalue getkeychanges getkeytimestamps batchquery

CLUSTERLIB=~/code/cluster-1.59
#CLUSTERLIB=~/code/cluster-1.50

clean:
	rm -f *.o tracequery clusterkeys clusterlib.a rollbackkey setkeyvalue getkeychanges getkeytimestamps batchquery *.out 

test: test1 test2

test1: adam.Explorer.EXE.out
	diff adam.Explorer.EXE.out test/adam.Explorer.EXE.out

adam.Explorer.EXE.out:
	./clusterkeys adam.Explorer.EXE.dist > adam.Explorer.EXE.out

test2: lie.OUTLOOK.EXE.out
	diff lie.OUTLOOK.EXE.out test/lie.OUTLOOK.EXE.out
	
lie.OUTLOOK.EXE.out:
	./clusterkeys lie.OUTLOOK.EXE.dist > lie.OUTLOOK.EXE.out

LIBS=../libtracequery/libtracequery.a ../libtracereplay/libtracereplay.a ../../timetravelstore/timetravelstore/libtimetravelstore.a ../../testandset/libtas.a ../../libhiredis/libhiredis.a clusterlib.a

#tracequery.o: tracequery.cpp
#	g++ -g -c tracequery.cpp

#tracequery_st.o: tracequery.cpp
#	g++ -g -c -D STANDALONE -o tracequery_st.o tracequery.cpp

main.o: main.cpp
	g++ -g -c main.cpp

tracequery: main.o $(LIBS)
	g++ -g -o tracequery main.o $(LIBS)


getkeytimestamps.o: getkeytimestamps.cpp
	g++ -g -c getkeytimestamps.cpp

getkeytimestamps: getkeytimestamps.o $(LIBS)
	g++ -g -o getkeytimestamps getkeytimestamps.o $(LIBS)

getkeychanges.o: getkeychanges.cpp
	g++ -g -c getkeychanges.cpp

getkeychanges: getkeychanges.o $(LIBS)
	g++ -g -o getkeychanges getkeychanges.o $(LIBS)

rollbackkey.o: rollbackkey.cpp
	g++ -g -c rollbackkey.cpp

rollbackkey: rollbackkey.o $(LIBS)
	g++ -g -o rollbackkey rollbackkey.o $(LIBS)

setkeyvalue.o: setkeyvalue.cpp
	g++ -g -c setkeyvalue.cpp

setkeyvalue: setkeyvalue.o $(LIBS)
	g++ -g -o setkeyvalue setkeyvalue.o $(LIBS)

batchquery.o: batchquery.cpp $(LIBS)
	g++ -g -c batchquery.cpp $(LIBS)

batchquery: batchquery.o $(LIBS)
	g++ -g -o batchquery batchquery.o $(LIBS)

batchrollback.o: batchrollback.cpp
	g++ -g -c batchrollback.cpp

batchrollback: batchrollback.o $(LIBS)
	g++ -g -o batchrollback batchrollback.o $(LIBS)

clusterkeys_lib.o: clusterkeys.cpp
	g++ -g -c -o clusterkeys_lib.o clusterkeys.cpp

clusterkeys.o: clusterkeys.cpp
	g++ -g -c -DSTANDALONE clusterkeys.cpp

clusterkeys: clusterkeys.o $(CLUSTERLIB)/src/cluster.o
	g++ -o clusterkeys clusterkeys.o $(CLUSTERLIB)/src/cluster.o

clusterlib.a: clusterkeys_lib.o $(CLUSTERLIB)/src/cluster.o
	ar r clusterlib.a clusterkeys_lib.o $(CLUSTERLIB)/src/cluster.o
