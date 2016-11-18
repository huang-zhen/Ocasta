
# To run a second ocasta module, comment first line, uncomment second line
OCASTA_VER := 
#OCASTA_VER := 1

EXECUTABLES  := ocasta listv revertv
ALL_EXECUTABLES := $(EXECUTABLES)
MODS    := ocasta_module$(OCASTA_VER).o
MODS_GEN := ocasta_module$(OCASTA_VER).mod.o
KMODS   := ocasta_module$(OCASTA_VER).ko
# Normal
#CFLAGS  += -g -Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wa,"-a"
EXTRA_CFLAGS  += -g -Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wa,-adlhs
# Generate List
#CFLAGS  += -g -Wall -D_FILE_OFFSET_BITS=32 -D_GNU_SOURCE
#EXTRA_CFLAGS  += -g -Wall -D_FILE_OFFSET_BITS=32 -D_GNU_SOURCE
LOADLIBES := -lpopt
DEPS    := .depend
SUBDIRS =
INSTALL_PROGRAM = install
INSTALL_DATA = install -m 644
sbindir = /usr/sbin
MODLIB:=/lib/modules/$(shell uname -r)/kernel/audit
#MODLIB:=/lib/modules/2.6.27-7-generic/kernel/audit

CONFDIR := /etc/ocasta

RCPROG := $(shell which chkconfig 2>/dev/null)
ifneq ($(strip $(RCPROG)),)
RCCMD := chkconfig --add ocasta
else
RCPROG := $(shell which update-rc.d 2>/dev/null)
ifneq ($(strip $(RCPROG)),)
RCCMD := update-rc.d ocasta defaults 9 99
endif
endif

# parameters for $CONFDIR/ocasta.conf
# these parameters can be set in the command line
SERVER=
OPTIONS=

ifdef KERNELRELEASE

obj-m := $(MODS)

ifeq ($(PATCHLEVEL), 4)
include $(TOPDIR)/Rules.make
endif

else

# the question mark allows exporting KDIR from the environment
KDIR ?= /lib/modules/$(shell uname -r)/build
#KDIR ?= /lib/modules/2.6.27-7-generic/build

.PHONY: all install
all: depend $(ALL_EXECUTABLES) $(MODS) $(SUBDIRS)

install: all modules_install
	$(INSTALL_PROGRAM) $(EXECUTABLES) $(sbindir); \
	$(INSTALL_PROGRAM) ocasta.rc /etc/init.d/ocasta; \
	$(RCCMD); \
	mkdir -p $(CONFDIR); \
	cp ocasta.conf $(CONFDIR)/ocasta.conf; \
	mkdir -p $(CONFDIR)/.dir; \
	mkdir -p $(CONFDIR)/uploaded; \
	cp ocasta_uploader /etc/cron.daily; \
	cp ocasta_uploader.sh $(CONFDIR)/ocasta_uploader.sh; \
	depmod -A;
	@ echo; echo; \
        echo "1. Add ocasta server in $(CONFDIR)/ocasta.conf"; \
        echo "2. To start ocasta, run '/etc/init.d/ocasta start'"

uninstall:
	$(RM) $(patsubst %,$(sbindir)/%,$(EXECUTABLES)); \
	$(RM) -rf $(MODLIB); \
	$(RM) /etc/init.d/ocasta; \
	$(RM) -rf $(CONFDIR);
	- rmmod ocasta_module;

ocasta.o: ocasta.c
	#$(CC) -g -Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wa,"-a" -c ocasta.c
	$(CC) -g -Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -c ocasta.c

file_seq.o: file_seq.c
	$(CC) -fPIC -g -Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -c file_seq.c

store_gconf_log.o: store_gconf_log.c
	$(CC) -fPIC -g -Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -c store_gconf_log.c `pkg-config --cflags --libs gconf-2.0`

ocasta: ocasta.o snapshot.o proc.o file_seq.o daemonize.o gconf_msg.o store_gconf_log.o

listv: listv.o versioning.o

revertv: revertv.o versioning.o

# for testing
snapshot: snapshot.o proc.o

testmsg: testmsg.c gconf_msg.c
	gcc -g -c testmsg.c
	gcc -g -c gconf_msg.c
	gcc -g -o testmsg testmsg.o gconf_msg.o

# snapshot: snapshot.o proc.o

.PHONY: $(SUBDIRS) modules_install
$(SUBDIRS):
	$(MAKE) -C $@

.PHONY: $(MODS)
$(MODS):
	$(MAKE) -C $(KDIR) SUBDIRS=$(CURDIR) modules

modules_install:
	$(MAKE) -C $(KDIR) SUBDIRS=$(CURDIR) MODLIB=$(MODLIB) modules_install

.PHONY: clean
clean: $(patsubst %, %-clean, $(SUBDIRS))
	- $(RM) *.o $(DEPS) $(MODS) $(MODS_GEN) $(patsubst %.o,%.c,$(MODS_GEN)) $(KMODS) .*.cmd; \
        $(RM) $(ALL_EXECUTABLES) $(RM) -r .tmp_versions

.PHONY: $(patsubst %, %-clean, $(SUBDIRS))
$(patsubst %, %-clean, $(SUBDIRS)):
	$(MAKE) -C $(patsubst %-clean, %, $@) clean

.PHONY: dep depend
dep depend: dep-files

.PHONY: dep-files
dep-files:
	@- $(CC) -MM $(filter-out $(patsubst %.o, %.c, $(MODS) $(MODS_GEN)), $(wildcard *.c)) >$(DEPS)

ifeq ($(DEPS), $(wildcard $(DEPS)))
include $(DEPS)
endif

endif
