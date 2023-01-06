all:	
	cd module ; make
	cd utilities ; make

module:
	cd module
	make clean
	make
	make reload

utilities:
	cd utilities
	make

clean:
	cd module ; make clean
	cd utilities ; make clean

install-old: all
	[ -d /etc/econet-gpio ] || sudo mkdir -p /etc/econet-gpio
	[ -d /etc/econet-gpio/printers ] || sudo cp -r printers /etc/econet-gpio
	[ -d /home/`whoami`/econetfs ] || mkdir -p /home/`whoami`/econetfs/0PIBRIDGE-00 || mkdir -p /home/`whoami`/econetfs/1STORAGE
	[ -f /etc/econet-gpio/pserv.sh ] || sudo cp config/pserv.sh /etc/econet-gpio
	[ -f /etc/udev/rules.d/90-econet.rules ] || sudo cp udev/90-econet.rules /etc/udev/rules.d/90-seconet.rules
	-sudo groupadd econet
	-sudo usermod -a -G econet `whoami`
	sudo chgrp econet utilities/econet-hpbridge utilities/econet-bridge utilities/econet-imm utilities/econet-monitor utilities/econet-test utilities/econet-clock utilities/econet-ledtest
	sudo chmod u=rx,g=rxs utilities/econet-bridge utilities/econet-hpbridge utilities/econet-imm utilities/econet-monitor utilities/econet-test utilities/econet-clock utilities/econet-ledtest
	sudo cp utilities/econet-bridge utilities/econet-hpbridge utilities/econet-monitor utilities/econet-test utilities/econet-clock utilities/econet-ledtest /usr/local/sbin
	sudo cp utilities/econet-imm utilities/econet-ipgw utilities/econet-notify utilities/econet-remote utilities/econet-fslist utilities/econet-trace /usr/local/bin
	sudo cp utilities/remove_xattr utilities/xattr_to_dotfile /usr/local/bin
	sudo cp module/econet-gpio.ko /lib/modules/`uname -r`/kernel/drivers/net
	sudo /usr/sbin/depmod

install:	install-old
	-sudo systemctl stop econethpb
	-sudo systemctl disable econethpb
	[ -f /etc/econet-gpio/econet.cfg ] || sudo cp config/econet.cfg /etc/econet-gpio/econet.cfg
	[ -f /etc/systemd/system/ecoentfs.service ] || (sudo cp systemd/econetfs.service /etc/systemd/system && sudo systemctl daemon-reload && sudo systemctl enable econetfs)
	@echo "Install routine finished. Please ensure you have 'arm_freq=1000' (or your chosen frequency) and 'force_turbo=1' in /boot/config.txt (see README). Then please reboot. Note that Econet library utilities for use on your server are NOT included, but they may be found distributed with BeebEm for Windows, and copied using the CopyFiles utility onto your network."	

install-hp:	install-old
	-sudo systemctl stop econetfs
	-sudo systemctl disable econetfs
	[ -f /etc/econet-gpio/econet-hpbridge.cfg ] || sudo cp config/econet-hpbridge.cfg-EconetPlusFileserver /etc/econet-gpio/econet-hpbridge.cfg
	[ -f /etc/systemd/system/econethpb.service ] || (sudo cp systemd/econethpb.service /etc/systemd/system && sudo systemctl daemon-reload && sudo systemctl enable econethpb)
	@echo "Install routine finished. Please ensure you have 'arm_freq=1000' (or your chosen frequency) and 'force_turbo=1' in /boot/config.txt (see README). Then please reboot. Note that Econet library utilities for use on your server are NOT included, but they may be found distributed with BeebEm for Windows, and copied using the CopyFiles utility onto your network."	
