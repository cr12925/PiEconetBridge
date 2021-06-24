ifneq ($(KERNELRELEASE),)

obj-m += econet-gpio.o
econet-gpio-y := econet-gpio-module.o

else

KDIR ?= /lib/modules/`uname -r`/build

all:
	$(MAKE) -I../include -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

reload:
	-sudo rmmod econet-gpio
	sudo insmod ./econet-gpio.ko
	sudo chmod a+rw /dev/econet-gpio

endif
