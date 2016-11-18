CFLAGS=-Wa,-adlhs
CC=gcc

all: sample libgconf_hook.so.1.0

sample: sample.c
	$(CC) sample.c -o sample `pkg-config --cflags --libs gconf-2.0`

gconf_msg.o: gconf_msg.c
	$(CC) -g -c gconf_msg.c

libgconf_hook.o: libgconf_hook.c
	$(CC) -D_GNU_SOURCE -g -c -fPIC libgconf_hook.c $(CFLAGS) `pkg-config --cflags --libs gconf-2.0`

libgconf_hook.so.1.0: libgconf_hook.o
	$(CC) -g -shared -Wl,-soname,libgconf_hook.so.1 $(CFLAGS) -o libgconf_hook.so.1.0 libgconf_hook.o ../kernel_logger/gconf_msg.o
	#$(CC) -g -shared -Wl,-soname,libgconf_hook.so.1 $(CFLAGS) -o libgconf_hook.so.1.0 libgconf_hook.o

testlibgconf.o: testlibgconf.c
	$(CC) -D_GNU_SOURCE -g -c -fPIC testlibgconf.c $(CFLAGS) `pkg-config --cflags --libs gconf-2.0`

testlibgconf: testlibgconf.o libgconf_hook.o
	$(CC) -g -o testlibgconf testlibgconf.o libgconf_hook.o ../kernel_logger/gconf_msg.o `pkg-config --cflags --libs gconf-2.0`

testlibgconf_se: testlibgconf.o libgconf_hook.o libgconf_msg_se.a
	$(CC) -g -o testlibgconf_se testlibgconf.o libgconf_hook.o libgconf_msg_se.a `pkg-config --cflags --libs gconf-2.0` -lbfd

se_gconf_msg.o: se_gconf_msg.c
	$(CC) -fPIC -g -c se_gconf_msg.c

backtrace-symbols.o: backtrace-symbols.c
	$(CC) -fPIC -g -c backtrace-symbols.c
 
libgconf_msg_se.a: se_gconf_msg.o ../kernel_logger/store_gconf_log.o ../kernel_logger/file_seq.o backtrace-symbols.o

	ar cr libgconf_msg_se.a se_gconf_msg.o ../kernel_logger/store_gconf_log.o ../kernel_logger/file_seq.o backtrace-symbols.o

libgconf_hook_se.so.1.0: libgconf_hook.o libgconf_msg_se.a
	$(CC) -g -shared -Wl,-soname,libgconf_hook.so.1 $(CFLAGS) -o libgconf_hook_se.so.1.0 libgconf_hook.o libgconf_msg_se.a -lbfd -lpthread

install:
	cp libgconf_hook.so.1.0 /usr/lib
	#cp ld.so.preload /etc/

uninstall:
	rm /etc/ld.so.preload
	rm /usr/lib/libgconf_hook.so.1.0

test:
	LD_PRELOAD=libgconf_hook.so.1.0 eog
	sort ~/gconf.log|uniq

clean:
	rm -rf *.o *.a *.so.1.0


