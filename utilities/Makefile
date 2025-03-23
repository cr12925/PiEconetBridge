GIT_VERSION := "$(shell git branch) $(shell git rev-parse --short HEAD)"
#GIT_VERSION := "CR Build tree"
CFLAGS=-g -O2 -I/usr/include/glib-2.0 -I/usr/lib/aarch64-linux-gnu/glib-2.0/include -I/usr/lib/arm-linux-gnueabihf/glib-2.0/include

fsop_objects := $(patsubst %.c,%.o,$(wildcard fsop/*.c))

all:	econet-monitor econet-imm econet-test pipe-eg econet-notify econet-ipgw econet-remote econet-hpbridge econet-fslist econet-ledtest econet-clock econet-trace econet-servers econet-poke econet-isnets unix2beeb

unix2beeb:	unix2beeb.c
	cc $(CFLAGS) -Wall -Wno-pointer-sign unix2beeb.c -o unix2beeb

econet-hpbridge:	Makefile econet-hpbridge.o econet-hpbridge-devinit.o econet-hpbridge-multitrunk.o fsv2.o $(fsop_objects)
	if [ -f .noexplain ]; then cc $(CFLAGS) -o econet-hpbridge econet-hpbridge.o econet-hpbridge-devinit.o econet-hpbridge-multitrunk.o fsv2.o $(fsop_objects) -lpthread -lssl -lcrypto -ljson-c -lglib-2.0; else cc $(CFLAGS) -o econet-hpbridge econet-hpbridge.o econet-hpbridge-devinit.o econet-hpbridge-multitrunk.o fsv2.o $(fsop_objects) -lpthread -lssl -lcrypto -lexplain -ljson-c -lglib-2.0; fi
	-chgrp econet econet-hpbridge

$(fsop_objects): %.o: %.c Makefile ../include/fs.h ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h
	cc $(CFLAGS) -DGIT_VERSION=\"$(GIT_VERSION)\" -I../include -c $< -Wall -Wno-pointer-sign -o $@

econet-hpbridge.o:	Makefile econet-hpbridge.c ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h ../include/econet-pserv.h
	cc $(CFLAGS) -I../include -I/usr/include/json-c -DGIT_VERSION=\"$(GIT_VERSION)\" -c econet-hpbridge.c -Wall

econet-hpbridge-devinit.o:	Makefile econet-hpbridge-devinit.c ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h ../include/econet-pserv.h
	cc $(CFLAGS) -I../include -I/usr/include/json-c -DGIT_VERSION=\"$(GIT_VERSION)\" -c econet-hpbridge-devinit.c -Wall

econet-hpbridge-multitrunk.o:	Makefile econet-hpbridge-multitrunk.c ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h ../include/econet-pserv.h
	cc $(CFLAGS) -I../include -I/usr/include/json-c -DGIT_VERSION=\"$(GIT_VERSION)\" -c econet-hpbridge-multitrunk.c -Wall

fsv2.o: Makefile fs.c ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h ../include/fs.h
	cc $(CFLAGS) -I../include -DGIT_VERSION=\"$(GIT_VERSION)\" -D BRIDGE_V2 -c fs.c -o fsv2.o -Wall -Wno-pointer-sign

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
	rm -f *.o econet-imm econet-test econet-bridge econet-monitor pipe-eg econet-notify econet-remote eb2 econet-hpbridge econet-ledtest econet-clock econet-trace fsop/*.o
