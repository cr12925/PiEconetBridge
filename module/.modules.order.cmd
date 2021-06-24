cmd_/home/pi/econet-onefile/module/modules.order := {   echo /home/pi/econet-onefile/module/econet-gpio.ko; :; } | awk '!x[$$0]++' - > /home/pi/econet-onefile/module/modules.order
