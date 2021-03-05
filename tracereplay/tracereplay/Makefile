all: tracereplay

clean:
	rm -f *.o tracereplay

LIBS=../libtracereplay/libtracereplay.a ../../timetravelstore/timetravelstore/libtimetravelstore.a ../../testandset/libtas.a ../../libhiredis/libhiredis.a

tracereplay.o: tracereplay.cpp
	g++ -g -c tracereplay.cpp

replay.o: replay.cpp
	g++ -g -c replay.cpp

keyhandle.o: keyhandle.cpp
	g++ -g -c keyhandle.cpp


tracereplay: tracereplay.o replay.o keyhandle.o $(LIBS)
	g++ -g -o tracereplay tracereplay.o replay.o keyhandle.o $(LIBS)


