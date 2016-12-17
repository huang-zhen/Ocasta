all: libtimetravelstore.a testtimetravelstore

clean:
	rm -f *.o *.a

timetravelstore.o: timetravelstore.cpp timetravelstore.h
	g++ -g -c timetravelstore.cpp

libtimetravelstore.a: timetravelstore.o
	ar r libtimetravelstore.a timetravelstore.o

testtimetravelstore.o: testtimetravelstore.cpp
	g++ -g -c testtimetravelstore.cpp

testtimetravelstore: testtimetravelstore.o libtimetravelstore.a ../../libhiredis/libhiredis.a ../../libtas/libtas.a
	g++ -g -o testtimetravelstore testtimetravelstore.o libtimetravelstore.a ../../libhiredis/libhiredis.a ../../libtas/libtas.a

test:
	./starttest
