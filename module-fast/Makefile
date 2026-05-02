ifneq ($(KERNELRELEASE),)

#MY_CFLAGS += -g 
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

obj-m += econet-fast.o
econet-fast-y := econet-fast-adlc-lowlevel.o econet-fast-adlc-ops.o econet-fast-rw-fops.o econet-fast-rw-ioctl.o econet-fast-irq.o econet-fast-module-ops.o econet-fast-netclock.o econet-fast-leds.o econet-fast-aun.o econet-fast-devices.o econet-fast-monitor-fops.o econet-fast-monitor-ioctl.o econet-fast-pbuf.o

else

KDIR ?= /lib/modules/`uname -r`/build

all:
	$(MAKE) -I../include -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	sudo cp econet-fast.ko /lib/modules/`uname -r`/kernel/drivers/net
	sudo depmod

reload: 
	-sudo rmmod econet-fast
	sudo insmod ./econet-fast.ko

endif
