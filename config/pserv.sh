#!/bin/bash

# PiEconetBridge print job utility
# Sends print jobs off, adds header files, etc.

#  (c) 2022 Chris Royle
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Usage:
# pserv.sh srvnet srvstn net stn username printer jobfile
#
# srvnet & srvstn are numeric server network & station 
# net & stn are numeric source network & station
# username is the name of the logged in user, if any (else 'ANON')
# printer is the unix printer name to send to, or an email address
# jobfile is the file containing the print job

# Path to configuration files
confpath=/etc/econet-gpio/printers

# Reads configuration from the following files, each in preference to the one before
# in $confpath
# default.header, default.conf
# <printername>.header, <printername>.conf
# <printername>.<username>.header, <printername>.<username>.conf

# The header files are just pre-pended to the print job, and run through
# sed to look for and substitute the following variables:
# _USERNAME_
# _SERVERNETWORK_
# _SERVERSTATION_
# _NETWORK_
# _STATION_
# _DATE_
# _TIME_

# The conf file contains a set of command line parameters which are added to lp or sendmail as appropriate before the destination

if [ "$#" != "8" ]
then
	echo "Usage: $0 <server net> <server station> <source net> <source stn> <source username> <printer or email addr> <acorn printer name> <filename>"
	exit
fi

srvnet=$1
srvstn=$2
net=$3
stn=$4
username=$5
dest=$6
acorndest=$7
file=$8
tmp=$(mktemp /tmp/econet-print.XXXXXXXXXX)
sedtmp=$(mktemp /tmp/econet-print.XXXXXXXXX)

header=""
cmdopts="" # Prepended command line options

if [ -f "${confpath}/${dest}.${username}.header" ]
then
	header="${confpath}/${dest}.${username}.header"
elif [ -f "${confpath}/${dest}.header" ]
then
	header="${conf}/${dest}.header"
elif [ -f "${confpath}/default.header" ]
then
	header="${confpath}/default.header"
fi

if [ -f ${confpath}/${dest}.${username}.conf ]
then
	. ${confpath}/${dest}.${username}.conf
elif [ -f ${confpath}/${dest}.conf ]
then
	. ${confpath}/${dest}.conf
elif [ -f ${confpath}/default.conf ]
then
	. ${confpath}/default.conf
fi

# Build the sed script
echo s/_SERVERNETWORK_/${1}/ >> $sedtmp
echo s/_SERVERSTATION_/${2}/ >> $sedtmp
echo s/_NETWORK_/${3}/ >> $sedtmp
echo s/_STATION_/${4}/ >> $sedtmp
echo s/_USERNAME_/${5}/ >> $sedtmp
echo s/_DATE_/`date +'%d.%m.%Y'`/ >> $sedtmp
echo s/_TIME_/`date +'%H:%M'`/ >> $sedtmp

# Put the header on the output

if [ "${header}" != "" ]
then
	/usr/bin/sed -f ${sedtmp} ${header} >> ${tmp}
fi

cat ${file} >> ${tmp}

if [[ "${dest}" =~ "@" ]]
then
		/usr/sbin/sendmail ${cmdopts} ${dest} < ${tmp} 2>&1 >/dev/null
else
		/usr/bin/lp ${cmdopts} -d ${dest} < ${tmp} 2>&1 >/dev/null
fi

# Clean up

rm ${sedtmp}
rm ${tmp}

exit 0
