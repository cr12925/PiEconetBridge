all:		build-module build-utilities 

build-module:
	[ -e /lib/modules/`uname -r`/build ] || sudo ln -s /usr/src/linux-headers-`uname -r` /lib/modules/`uname -r`/build
	[ -f include/econet-gpio-kernel-mode.h ] || touch include/econet-gpio-kernel-mode.h
	cd module ; make clean ; make

build-utilities:
	cd utilities ; make

install:	all install-module install-utilities

install-mkgroup:
	-sudo groupadd econet
	-sudo usermod -a -G econet `whoami`

install-module:	install-mkgroup build-module
	[ -e /etc/udev/rules.d/90-econet.rules ] || sudo cp udev/90-econet.rules /etc/udev/rules.d/90-seconet.rules
	sudo cp module/econet-gpio.ko /lib/modules/`uname -r`/kernel/drivers/net
	sudo /usr/sbin/depmod

install-utilities:	install-mkgroup build-utilities
	[ -e /etc/econet-gpio ] || sudo mkdir -p /etc/econet-gpio
	[ -e /etc/econet-gpio/printers ] || sudo cp -r printers /etc/econet-gpio
	[ -e /home/`whoami`/econetfs ] || (mkdir -p /home/`whoami`/econetfs/0PIBRIDGE-00 && mkdir -p /home/`whoami`/econetfs/1STORAGE)
	-[ -e /home/`whoami`/econetfs/0PIBRIDGE-00 ] && mkdir -p /home/`whoami`/econetfs/0PIBRIDGE-00/SYSTEM && cp FS/PIFSTOOL /home/`whoami`/econetfs/0PIBRIDGE-00/SYSTEM/PIFSTOOL 
	[ -e /etc/econet-gpio/pserv.sh ] || sudo cp config/pserv.sh /etc/econet-gpio
	-sudo systemctl stop econet-hpbridge
	sudo chgrp econet utilities/econet-hpbridge utilities/econet-imm utilities/econet-monitor utilities/econet-test utilities/econet-clock utilities/econet-ledtest
	sudo chmod u=rx,g=rxs utilities/econet-hpbridge utilities/econet-imm utilities/econet-monitor utilities/econet-test utilities/econet-clock utilities/econet-ledtest
	sudo cp utilities/econet-hpbridge utilities/econet-monitor utilities/econet-test utilities/econet-clock utilities/econet-ledtest /usr/local/sbin
	sudo cp utilities/econet-imm utilities/econet-ipgw utilities/econet-notify utilities/econet-remote utilities/econet-fslist utilities/econet-trace utilities/econet-servers utilities/econet-isnets /usr/local/bin
	sudo cp utilities/remove_xattr utilities/xattr_to_dotfile /usr/local/bin
	utilities/config-mangle config/econet-hpbridge.cfg-EconetPlusFileserver
	utilities/config-mangle config/econet-hpbridge.cfg-EconetFSPlusAcornAUN
	utilities/config-mangle config/econet-hpbridge.cfg-EconetPlusFileserverAndTrunk
	utilities/config-mangle config/econet-hpbridge.cfg-EconetFSPlusDynamicAUN
	utilities/config-mangle systemd/econet-hpbridge.service
	[ -e /etc/econet-gpio/econet-hpbridge.cfg ] || (sudo cp config/econet-hpbridge.cfg-EconetPlusFileserver.local /etc/econet-gpio/econet-hpbridge.cfg ; sudo chown `whoami` /etc/econet-gpio/econet-hpbridge.cfg )
	[ -e /etc/systemd/system/econet-hpbridge.service ] || sudo cp systemd/econet-hpbridge.service.local /etc/systemd/system/econet-hpbridge.service
	sudo cp BEEBMEM /etc/econet-gpio
	-sudo systemctl daemon-reload
	-sudo systemctl enable econet-hpbridge
	-sudo systemctl start econet-hpbridge
	@cat docs/Makefile-MOTD


install-hp-utilities:	install-utilities

install-hp:	install

setuid:		install-module install-hp-utilities
	-sudo systemctl stop econet-hpbridge
	-sudo chown root /usr/local/sbin/econet-hpbridge
	-sudo chmod u+s /usr/local/sbin/econet-hpbridge
	-sudo systemctl start econet-hpbridge

clean:
	cd module ; make clean
	cd utilities ; make clean

eeprom-general:
	cd dts ; ./dtcompile

eeprom-v1: eeprom-general
	@cat v2eeprom/v1warning.txt
	@read a
	sudo cp dts/econet-gpio-v1.dtbo /boot/overlays
	@echo Now add "dtoverlay=econet-gpio-v1" to your config.txt

eep: eeprom-general
	@cat v2eeprom/warning.txt
	@read a
	[ -d hats ] || git clone https://github.com/raspberrypi/hats.git hats
	cd hats/eepromutils ; make
	hats/eepromutils/eepmake v2eeprom/econet_eeprom.txt v2eeprom/econet-gpio-v2.eep dts/econet-gpio-v2.dtb -c v2eeprom/Copyright.txt v2eeprom/ReadMe.txt

eeprom-v2: eeprom-general eep
	dd if=/dev/zero ibs=1k count=8 of=v2eeprom/blank.eep
	sudo hats/eepromutils/eepflash.sh -w -f=v2eeprom/blank.eep -t=24c64
	sudo hats/eepromutils/eepflash.sh -w -f=v2eeprom/econet-gpio-v2.eep -t=24c64
	@echo +++ Now comment out the two lines you added to config.txt and reboot!

