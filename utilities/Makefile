all:	econet-bridge econet-monitor econet-imm econet-test pipe-eg econet-notify econet-ipgw econet-remote econet-hpbridge econet-fslist econet-ledtest econet-clock econet-trace

econet-hpbridge:	econet-hpbridge.o fsv2.o 
	cc -o econet-hpbridge econet-hpbridge.o fsv2.o -lpthread -lexplain
	-chgrp econet econet-hpbridge
	-sudo setcap cap_net_admin=pe econet-hpbridge

econet-hpbridge.o:	econet-hpbridge.c ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h ../include/econet-pserv.h
	cc -c econet-hpbridge.c -Wall

fsv2.o: fs.c ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h
	cc -D BRIDGE_V2 -c fs.c -o fsv2.o -Wall -Wno-pointer-sign

fs.o:	fs.c ../include/econet-gpio-consumer.h 
	cc -c fs.c -Wall -Wno-pointer-sign

econet-bridge: econet-bridge.o fs.o sockets.o -lexplain

econet-monitor: econet-monitor.o

econet-imm: econet-imm.o

econet-test: econet-test.o
 
econet-ledtest: econet-ledtest.o

econet-notify: econet-notify.o econet-pipe.o

econet-remote: econet-remote.o econet-pipe.o

econet-fslist: econet-fslist.o econet-pipe.o

econet-ipgw: econet-ipgw.o econet-pipe.o

econet-trace: econet-trace.o econet-pipe.o

pipe-eg: pipe-eg.o econet-pipe.o

econet-clock: econet-clock.o

econet-bridge.o: econet-bridge.c fs.c sockets.c ../include/econet-gpio-consumer.h
	cc -c econet-bridge.c -Wall
	cc -c fs.c -Wall -Wno-pointer-sign 
	cc -c sockets.c -Wall

econet-monitor.o: econet-monitor.c ../include/econet-gpio-consumer.h

econet-imm.o: econet-imm.c ../include/econet-gpio-consumer.h

econet-test.o: econet-test.c ../include/econet-gpio-consumer.h

econet-ledtest.o: econet-ledtest.c ../include/econet-gpio-consumer.h

pipe-eg.o: pipe-eg.c econet-pipe.c ../include/econet-gpio-consumer.h

econet-pipe.o: econet-pipe.c ../include/econet-gpio-consumer.h

econet-notify.o: econet-notify.c econet-pipe.c ../include/econet-gpio-consumer.h

econet-remote.o: econet-remote.c econet-pipe.c ../include/econet-gpio-consumer.h

econet-fslist.o: econet-fslist.c econet-pipe.c ../include/econet-gpio-consumer.h

econet-ipgw.o: econet-ipgw.c econet-pipe.c ../include/econet-gpio-consumer.h

econet-clock.o: econet-clock.c ../include/econet-gpio-consumer.h

econet-trace.o: econet-trace.c ../include/econet-gpio-consumer.h ../include/econet-hpbridge.h

clean:
	rm -f *.o econet-imm econet-test econet-bridge econet-monitor pipe-eg econet-notify econet-remote eb2 econet-hpbridge econet-ledtest econet-clock econet-trace
