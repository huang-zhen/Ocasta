all: libtracereplay.a

clean:
	rm -f *.o *.a

appstatestore.o: appstatestore.cpp
	g++ -g -c appstatestore.cpp

keyhandle.o: keyhandle.cpp
	g++ -g -c keyhandle.cpp

libtracereplay.a: keyhandle.o appstatestore.o
	ar r libtracereplay.a keyhandle.o appstatestore.o

