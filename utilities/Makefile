GIT_VERSION := "$(shell git branch) $(shell git rev-parse --short HEAD)"

all:	econet-monitor econet-imm econet-test pipe-eg econet-notify econet-ipgw econet-remote econet-hpbridge econet-fslist econet-ledtest econet-clock econet-trace econet-servers econet-poke econet-isnets

econet-hpbridge:	econet-hpbridge.o fsv2.o 
	if [ -f .noexplain ]; then cc -g -o econet-hpbridge econet-hpbridge.o fsv2.o -lpthread -lssl -lcrypto; else cc -g -o econet-hpbridge econet-hpbridge.o fsv2.o -lpthread -lssl -lcrypto -lexplain; fi
	-chgrp econet econet-hpbridge

econet-hpbridge.o:	Makefile econet-hpbridge.c ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h ../include/econet-pserv.h
	cc -g -DGIT_VERSION=\"$(GIT_VERSION)\" -c econet-hpbridge.c -Wall

fsv2.o: Makefile fs.c ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h
	cc -DGIT_VERSION=\"$(GIT_VERSION)\" -D BRIDGE_V2 -g -c fs.c -o fsv2.o -Wall -Wno-pointer-sign

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
	rm -f *.o econet-imm econet-test econet-bridge econet-monitor pipe-eg econet-notify econet-remote eb2 econet-hpbridge econet-ledtest econet-clock econet-trace
