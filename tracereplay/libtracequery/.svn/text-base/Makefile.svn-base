all: libtracequery.a

#FLAGS=-m32 -g -c
FLAGS=-g -c

clean:
	rm -f *.o *.a

tracequery.o: tracequery.cpp tracequery.h
	g++ $(FLAGS) tracequery.cpp

keyhandle.o: keyhandle.cpp keyhandle.h
	g++ $(FLAGS) keyhandle.cpp

libtracequery.a: tracequery.o
	ar r libtracequery.a tracequery.o

