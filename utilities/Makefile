GIT_VERSION := "$(shell git rev-parse --abbrev-ref HEAD) $(shell git rev-parse --short HEAD)"
EXTRALIBS= # -lsystemd
CFLAGS=-g -O2 -I../include $(shell pkg-config --cflags glib-2.0) -I/usr/include/json-c

econet_hpb_objects := $(patsubst %.c,%.o,$(wildcard econet-hpbridge*.c))
econet_hpb_modules := $(patsubst %.c,%.o,$(wildcard modules/*.c))
fsop_objects := $(patsubst %.c,%.o,$(wildcard modules/fsop/*.c))
libs := -lpthread -lssl -lcrypto -ljson-c -lglib-2.0 -lssh2 $(EXTRALIBS)

all:	econet-monitor econet-imm econet-test pipe-eg econet-notify econet-ipgw econet-remote econet-hpbridge econet-fslist econet-ledtest econet-clock econet-trace econet-servers econet-poke econet-isnets unix2beeb

pre-build:
	rm -f modules/fsop/fsop_00_bridge.o # Otherwise it doesn't update GIT_VERSION

unix2beeb:	unix2beeb.c
	cc $(CFLAGS) -Wall -Wno-pointer-sign unix2beeb.c -o unix2beeb

econet-hpbridge:	pre-build
	@$(MAKE) real-hpb-build
	
real-hpb-build: Makefile $(fsop_objects) $(econet_hpb_objects) $(econet_hpb_modules)
	if [ -f .noexplain ]; then cc $(CFLAGS) -o econet-hpbridge $(econet_hpb_objects) $(econet_hpb_modules) $(fsop_objects) $(libs); else cc $(CFLAGS) -o econet-hpbridge $(econet_hpb_objects) $(econet_hpb_modules) $(fsop_objects) $(libs) -lexplain; fi
	-chgrp econet econet-hpbridge
	-sudo setcap CAP_NET_RAW=ep ${CURDIR}/econet-hpbridge

$(fsop_objects): %.o: %.c Makefile ../include/fs.h ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h
	cc $(CFLAGS) -DGIT_VERSION=\"$(GIT_VERSION)\" -I../include -c $< -Wall -Wno-pointer-sign -o $@

$(econet_hpb_objects): %.o: %.c Makefile ../include/fs.h ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h ../include/econet-hpbridge-modules.h
	cc $(CFLAGS) -DGIT_VERSION=\"$(GIT_VERSION)\" -I/usr/include/json-c -I../include -c $< -Wall -Wno-pointer-sign -o $@

$(econet_hpb_modules): %.o: %.c Makefile ../include/fs.h ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h ../include/econet-hpbridge-modules.h
	cc $(CFLAGS) -DGIT_VERSION=\"$(GIT_VERSION)\" -I/usr/include/json-c -I../include -c $< -Wall -Wno-pointer-sign -o $@

fast-test.o: Makefile econet-hpbridge-fast.c ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h ../include/fs.h 
	cc $(CFLAGS) -DFAST_TEST -I../include -I/usr/include/json-c -DGIT_VERSION=\"$(GIT_VERSION)\" -c econet-hpbridge-fast.c -o fast-test.o -Wall

fast-test: Makefile fast-test.o
	cc $(CFLAGS) fast-test.o -o fast-test -lpthread

econet-monitor: econet-monitor.o

econet-imm: econet-imm.o

econet-test: econet-test.o
 
econet-ledtest: econet-ledtest.o

econet-notify: econet-notify.o econet-pipe.o

econet-remote: econet-remote.o econet-pipe.o

econet-fslist: econet-fslist.o econet-pipe.o

econet-isnets: econet-isnets.o econet-pipe.o

econet-servers: econet-servers.o econet-pipe.o

econet-ipgw: econet-ipgw.o econet-pipe.o

econet-trace: econet-trace.o econet-pipe.o

pipe-eg: pipe-eg.o econet-pipe.o

econet-clock: econet-clock.o

econet-poke: econet-poke.o econet-pipe.o

econet-monitor.o: econet-monitor.c ../include/econet-gpio-consumer.h

econet-imm.o: econet-imm.c ../include/econet-gpio-consumer.h

econet-test.o: econet-test.c ../include/econet-gpio-consumer.h

econet-ledtest.o: econet-ledtest.c ../include/econet-gpio-consumer.h

pipe-eg.o: pipe-eg.c econet-pipe.c ../include/econet-gpio-consumer.h

econet-pipe.o: econet-pipe.c ../include/econet-gpio-consumer.h

econet-notify.o: econet-notify.c econet-pipe.c ../include/econet-gpio-consumer.h

econet-remote.o: econet-remote.c econet-pipe.c ../include/econet-gpio-consumer.h

econet-fslist.o: econet-fslist.c econet-pipe.c ../include/econet-gpio-consumer.h

econet-isnets.o: econet-isnets.c econet-pipe.c ../include/econet-gpio-consumer.h

econet-servers.o: econet-servers.c econet-pipe.c ../include/econet-gpio-consumer.h

econet-ipgw.o: econet-ipgw.c econet-pipe.c ../include/econet-gpio-consumer.h

econet-clock.o: econet-clock.c ../include/econet-gpio-consumer.h

econet-trace.o: econet-trace.c ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h

econet-poke.o: econet-poke.c econet-pipe.c ../include/econet-gpio-consumer.h

clean:
	rm -f *.o econet-imm econet-test econet-bridge econet-monitor pipe-eg econet-notify econet-remote eb2 econet-hpbridge econet-ledtest econet-clock econet-trace modules/*.o modules/fsop/*.o
