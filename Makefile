all:		install-hp

install:	install-hp

install-mkgroup:
	-sudo groupadd econet
	-sudo usermod -a -G econet `whoami`

install-module:	install-mkgroup
	cd module ; make clean ; make
	[ -f /etc/udev/rules.d/90-econet.rules ] || sudo cp udev/90-econet.rules /etc/udev/rules.d/90-seconet.rules
	sudo cp module/econet-gpio.ko /lib/modules/`uname -r`/kernel/drivers/net
	sudo /usr/sbin/depmod

utilities: install-mkgroup
	-sudo systemctl stop econet-hpbridge
	cd utilities ; make

install-utilities:	install-mkgroup utilities
	[ -d /etc/econet-gpio ] || sudo mkdir -p /etc/econet-gpio
	[ -d /etc/econet-gpio/printers ] || sudo cp -r printers /etc/econet-gpio
	[ -d /home/`whoami`/econetfs ] || mkdir -p /home/`whoami`/econetfs/0PIBRIDGE-00 || mkdir -p /home/`whoami`/econetfs/1STORAGE
	[ -f /etc/econet-gpio/pserv.sh ] || sudo cp config/pserv.sh /etc/econet-gpio
	sudo chgrp econet utilities/econet-hpbridge utilities/econet-imm utilities/econet-monitor utilities/econet-test utilities/econet-clock utilities/econet-ledtest
	sudo chmod u=rx,g=rxs utilities/econet-hpbridge utilities/econet-imm utilities/econet-monitor utilities/econet-test utilities/econet-clock utilities/econet-ledtest
	sudo cp utilities/econet-hpbridge utilities/econet-monitor utilities/econet-test utilities/econet-clock utilities/econet-ledtest /usr/local/sbin
	sudo cp utilities/econet-imm utilities/econet-ipgw utilities/econet-notify utilities/econet-remote utilities/econet-fslist utilities/econet-trace utilities/econet-servers /usr/local/bin
	sudo cp utilities/remove_xattr utilities/xattr_to_dotfile /usr/local/bin
	utilities/config-mangle config/econet-hpbridge.cfg-EconetPlusFileserver
	utilities/config-mangle config/econet-hpbridge.cfg-EconetFSPlusAcornAUN
	utilities/config-mangle config/econet-hpbridge.cfg-EconetPlusFileserverAndTrunk
	utilities/config-mangle config/econet-hpbridge.cfg-EconetFSPlusDynamicAUN
	utilities/config-mangle systemd/econet-hpbridge.service
	[ -f /etc/econet-gpio/econet-hpbridge.cfg ] || sudo cp config/econet-hpbridge.cfg-EconetPlusFileserver.local /etc/econet-gpio/econet-hpbridge.cfg
	[ -f /etc/systemd/system/econet-hpbridge.service ] || sudo cp systemd/econet-hpbridge.service.local /etc/systemd/system/econet-hpbridge.service
	sudo cp BEEBMEM /etc/econet-gpio

install-hp-utilities:	install-utilities
	-sudo systemctl daemon-reload
	-sudo systemctl enable econet-hpbridge
	-sudo systemctl start econet-hpbridge
	@echo "Install routine finished. Please ensure you have 'arm_freq=1000' (or your chosen frequency) and 'force_turbo=1' in /boot/config.txt (see README). Then please reboot. Note that Econet library utilities for use on your server are NOT included, but they may be found distributed with BeebEm for Windows, and copied using the CopyFiles utility onto your network."	

install-hp:	install-module install-hp-utilities

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
	cp dts/econet-gpio-v1.dtbo /boot/overlays
	@echo Now add "dtoverlay=econet-gpio-v1" to your config.txt

eep: eeprom-general
	@cat v2eeprom/warning.txt
	@read a
	[ -d hats ] || git clone https://github.com/raspberrypi/hats.git hats
	cd hats/eepromutils ; make
	hats/eepromutils/eepmake v2eeprom/econet_eeprom.txt v2eeprom/econet-gpio-v2.eep dts/econet-gpio-v2.dtb -c v2eeprom/Copyright.txt v2eeprom/ReadMe.txt

eeprom-v2: eeprom-general eep
	dd if=/dev/zero ibs=1k count=8 of=blank.eep
	sudo hats/eepromutils/eepflash.sh -w -f=blank.eep -t=24c64
	sudo hats/eepromutils/eepflash.sh -w -f=v2eeprom/econet-gpio-v2.eep -t=24c64
