all:	econet-bridge econet-monitor econet-imm econet-test pipe-eg econet-notify econet-ipgw

econet-bridge: econet-bridge.o fs.o sockets.o

econet-monitor: econet-monitor.o

econet-imm: econet-imm.o

econet-test: econet-test.o
 
econet-notify: econet-notify.o econet-pipe.o

econet-ipgw: econet-ipgw.o econet-pipe.o

pipe-eg: pipe-eg.o econet-pipe.o

econet-bridge.o: econet-bridge.c fs.c sockets.c ../include/econet-gpio-consumer.h
	cc -c econet-bridge.c -Wall
	cc -c fs.c -Wall -Wno-pointer-sign 
	cc -c sockets.c -Wall

econet-monitor.o: econet-monitor.c ../include/econet-gpio-consumer.h

econet-imm.o: econet-imm.c ../include/econet-gpio-consumer.h

econet-test.o: econet-test.c ../include/econet-gpio-consumer.h

pipe-eg.o: pipe-eg.c econet-pipe.o ../include/econet-gpio-consumer.h

econet-pipe.o: econet-pipe.c ../include/econet-gpio-consumer.h

econet-notify.o: econet-notify.c econet-pipe.o ../include/econet-gpio-consumer.h

econet-ipgw.o: econet-ipgw.c econet-pipe.o ../include/econet-gpio-consumer.h

clean:
	rm -f *.o econet-imm econet-test econet-bridge econet-monitor pipe-eg econet-notify
