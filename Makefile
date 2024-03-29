all:	install-old

install-module:	install-mkgroup
	cd module ; make clean ; make
	[ -f /etc/udev/rules.d/90-econet.rules ] || sudo cp udev/90-econet.rules /etc/udev/rules.d/90-seconet.rules
	sudo cp module/econet-gpio.ko /lib/modules/`uname -r`/kernel/drivers/net
	sudo /usr/sbin/depmod

install-mkgroup:
	-sudo groupadd econet
	-sudo usermod -a -G econet `whoami`

utilities: install-mkgroup
	cd utilities ; make

install-utilities:	install-mkgroup utilities
	[ -d /etc/econet-gpio ] || sudo mkdir -p /etc/econet-gpio
	[ -d /etc/econet-gpio/printers ] || sudo cp -r printers /etc/econet-gpio
	[ -d /home/`whoami`/econetfs ] || mkdir -p /home/`whoami`/econetfs/0PIBRIDGE-00 || mkdir -p /home/`whoami`/econetfs/1STORAGE
	[ -f /etc/econet-gpio/pserv.sh ] || sudo cp config/pserv.sh /etc/econet-gpio
	sudo chgrp econet utilities/econet-hpbridge utilities/econet-bridge utilities/econet-imm utilities/econet-monitor utilities/econet-test utilities/econet-clock utilities/econet-ledtest
	sudo chmod u=rx,g=rxs utilities/econet-bridge utilities/econet-hpbridge utilities/econet-imm utilities/econet-monitor utilities/econet-test utilities/econet-clock utilities/econet-ledtest
	sudo cp utilities/econet-bridge utilities/econet-hpbridge utilities/econet-monitor utilities/econet-test utilities/econet-clock utilities/econet-ledtest /usr/local/sbin
	sudo cp utilities/econet-imm utilities/econet-ipgw utilities/econet-notify utilities/econet-remote utilities/econet-fslist utilities/econet-trace utilities/econet-servers /usr/local/bin
	sudo cp utilities/remove_xattr utilities/xattr_to_dotfile /usr/local/bin
	utilities/config-mangle config/econet.cfg
	utilities/config-mangle config/econet-hpbridge.cfg-EconetPlusFileserver
	utilities/config-mangle config/econet-hpbridge.cfg-EconetFSPlusAcornAUN
	utilities/config-mangle config/econet-hpbridge.cfg-EconetPlusFileserverAndTrunk
	utilities/config-mangle config/econet-hpbridge.cfg-EconetFSPlusDynamicAUN
	utilities/config-mangle systemd/econetfs.service
	utilities/config-mangle systemd/econethpb.service
	[ -f /etc/econet-gpio/econet.cfg ] || sudo cp config/econet.cfg.local /etc/econet-gpio/econet.cfg
	[ -f /etc/systemd/system/econetfs.service ] || sudo cp systemd/econetfs.service.local /etc/systemd/system/econetfs.service
	[ -f /etc/econet-gpio/econet-hpbridge.cfg ] || sudo cp config/econet-hpbridge.cfg-EconetPlusFileserver.local /etc/econet-gpio/econet-hpbridge.cfg
	[ -f /etc/systemd/system/econethpb.service ] || sudo cp systemd/econethpb.service.local /etc/systemd/system/econethpb.service

install-old-utilities:	install-utilities
	-sudo systemctl daemon-reload
	-sudo systemctl disable econethpb
	-sudo systemctl stop econethpb
	-sudo systemctl enable econetfs
	-sudo systemctl start econetfs
	@echo "Install routine finished. Please ensure you have 'arm_freq=1000' (or your chosen frequency) and 'force_turbo=1' in /boot/config.txt (see README). Then please reboot. Note that Econet library utilities for use on your server are NOT included, but they may be found distributed with BeebEm for Windows, and copied using the CopyFiles utility onto your network."	

install-hp-utilities:	install-utilities
	-sudo systemctl daemon-reload
	-sudo systemctl stop econetfs
	-sudo systemctl disable econetfs
	-sudo systemctl enable econethpb
	-sudo systemctl start econethpb
	@echo "Install routine finished. Please ensure you have 'arm_freq=1000' (or your chosen frequency) and 'force_turbo=1' in /boot/config.txt (see README). Then please reboot. Note that Econet library utilities for use on your server are NOT included, but they may be found distributed with BeebEm for Windows, and copied using the CopyFiles utility onto your network."	

install-old:	install-module install-old-utilities

install-hp:	install-module install-hp-utilities

clean:
	cd module ; make clean
	cd utilities ; make clean

