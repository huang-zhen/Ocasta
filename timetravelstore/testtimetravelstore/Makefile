all: testtimetravelstore

clean:
	rm -f *.o testtimetravelstore

testtimetravelstore.o: testtimetravelstore.cpp
	g++ -g -c testtimetravelstore.cpp

testtimetravelstore: testtimetravelstore.o ../timetravelstore/libtimetravelstore.a ../../libhiredis/libhiredis.a ../../testandset/libtas.a
	g++ -g -o testtimetravelstore testtimetravelstore.o ../timetravelstore/libtimetravelstore.a ../../libhiredis/libhiredis.a ../../testandset/libtas.a


