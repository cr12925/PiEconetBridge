ifneq ($(KERNELRELEASE),)

obj-m += econet-gpio.o
econet-gpio-y := econet-gpio-module.o

else

KDIR ?= /lib/modules/`uname -r`/build
#BUILDDIR = /home/pi/econet-gpio-module/module

all:
	$(MAKE) -I../include -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	sudo cp econet-gpio.ko /lib/modules/`uname -r`/kernel/drivers/net
	sudo depmod

reload: 
	-sudo rmmod econet-gpio
	sudo insmod ./econet-gpio.ko

endif
