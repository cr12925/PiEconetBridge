#!/bin/bash

# Syntax
#
# tapes.sh <fsrootdir> format <tapename>
#   - Creates a new "tape" (a .tar file) with empty contents
#     called <tapename>
# tapes.sh <fsrootdir> mount <tapename> <tapedrivenumber>
#   - Untars the "tape" and makes a link to TapeDrives/<tapedrivenumber>
# tapes.sh <fsrootdir> backup <tapename> <tapedrivenumber> <discdirname> <partition>
#   - <discdirname> is the full name of the directory containing the disc
#     to be backed up - e.g. 0PIBRIDGE-00 (i.e. *with* the leading 0 dir
#     FS drive 0, which will get stripped off by this script)
#   - Backs up the identified FS disc to partition <partition> on <tapename> in <tapedrivenumber>
# tapes.sh <fsrootdir> umount <tapename> <tapedrivenumber> 
#  - Tars the "tape"  back up and removes the link to TapeDrives/<tapedrivenumber>
#
# tapes.sh <fsrootdir> drivestate <ignored> <tapedrivenumber>
#  - Returns success if there's a tape in the drive
#  - Otherwise error 14

TAR=/usr/bin/tar
LN="/usr/bin/ln -s"
TAREXTENSION=".tar"
TARCREATEPARAMS="--xattrs -cf"
TAREXTRACTPARAMS="--xattrs -xf"
TARCREATECMD="${TAR} ${TARCREATEPARAMS}"
TAREXTRACTCMD="${TAR} ${TAREXTRACTPARAMS}"
MAXTAPEDRIVES=4 # If you change this, you'll need to change it in fs.h as well (FS_MAX_TAPE_DRIVES macro

if [ "$#" -lt 3 ]; then
	#echo "Not enough parameters"
	exit 10
fi

fsdir=$1
cmd=$2
tapename=$3
tapedrive=$4
discdirname=$5
partition=$6

if [ $# -eq 6 ]; then
	discname=${discdirname:1} 
else
	discname=""
fi

if [ "$cmd" != "format" ]; then
	if [ "$tapedrive" -gt "$MAXTAPEDRIVES" ]; then
		exit 17
	fi
fi

numparams=$#

#
# Error return codes from this script (return of 0 is success)
#
# 1 Bad Server directory
# 2 Tape already mounted (on a mount operation)
# 3 Bad command
# 4 Tape not mounted (on an unmount operation)
# 5 Unable to make/delete mount directory for tape (on a mount/umount operation)
# 6 Tape drive in use (on a mount operation) / Cannot remove drive link (on umount)
# 7 Attempt to mount a tape but its mount directory exists (on a mount operation)
# 8 Unpack of tar file failed (on a mount operation)
# 9 Creating tape drive link failed (on a mount operation)
# 10 Wrong number of parameters
# 11 Unmount failed - tar unsuccessful
# 12 Tape format failed
# 13 Invalid partition number (for backup)
# 14 Drive empty
# 15 Drive fault (can't make $mountdir or link to $tapedrivepath)
# 16 Backup failed - tape will be corrupt
# 17 Invalid tape drive number
# 18 Tape not found

if [ "${fsdir:0:1}" != "/" ]; then exit 1; fi

if [ "${#fsdir}" -lt "3" ]; then exit 1; fi

# If you change Tapes or TapeDrives in these definitions, you'll have to update the definition of FS_DIR_TAPEDRIVES and FS_DIR_TAPES in fs.h

tapedir="$fsdir/Tapes"

tapedrivedir="$fsdir/TapeDrives"
tarname="$tapedir/${tapename}${TAREXTENSION}"
mountdir="$tapedir/${tapename}.mnt"
tapedrivepath="$tapedrivedir/$tapedrive"
tapedrivepathrelative="../TapeDrives/$tapedrive"

echo "Command: $0 $*"
echo "FS Dir: $fsdir"
echo "Tape Dir: $tapedir"
echo "Tape Drives Dir: $tapedrivedir"
echo ".tar name: $tarname"
echo "Mount directory: $mountdir"

if [ ! -d $tapedrivedir ]; then
	mkdir -p $tapedrivedir
fi

if [ ! -d $tapedir ]; then
	mkdir -p $tapedir
fi

cd $tapedrivedir

check_mounted () {

	local mountdir=$1

	if [ -d $mountdir ]; then return 1; fi
	
	return 0

}

tape_drivestate () {

	if [ -L "$tapedrivepath" ]; then
		if [ -d "$tapedrivepath" ]; then
			return 0
		fi
	fi

	return 14
}

tape_mount () {
	tapedir=$1
	tarname=$2
	mountdir=$3
	tapedrivepath=$4

if [ "$numparams" -lt 4 ]; then
	echo "Not enough parameters"
	exit 10
fi

	check_mounted $mountdir
	is_mounted=$?

	if [ "$is_mounted" -eq 1 ]; then return 2; fi

	if [ -e $tapedrivepath ]; then return 6; fi

	if [ ! -e $tarname ]; then return 18; fi

	if [ -e $mountdir ]; then return 7; fi

	mkdir $mountdir

	if [ "$?" -ne "0" ]
	then
		return 5
	fi

	cd $mountdir

	$TAREXTRACTCMD $tarname

	if [ "$?" -ne "0" ]; then 
		rm -rf $mountdir
		return 8
	fi

	#echo $tapedrivepathrelative

	cd $tapedir

	$LN $mountdir $tapedrivepathrelative

	if [ "$?" -ne "0" ]; then
		rm $tapedrivepath
		rm -rf $mountdir
		return 9
	fi

	return 0
}

tape_umount () {        
#	tapedir=$1
        #tarname=$2
        #mountdir=$3
        #tapedrivepath=$4

if [ "$numparams" -lt 4 ]; then
	#echo "Not enough parameters"
	exit 10
fi

        check_mounted $mountdir
        is_mounted=$?

        if [ "$is_mounted" -eq 0 ]; then return 4; fi

        if [ ! -d $tapedrivepath ]; then return 4; fi

        if [ ! -d $mountdir ]; then return 4; fi

	cd $mountdir

	$TARCREATECMD $tarname .

	if [ "$?" -ne "0" ]; then
		return 11
	fi

	rm -rf $mountdir

	if [ "$?" -ne "0" ]; then
		return 5
	fi

	rm $tapedrivepath

	if [ "$?" -ne "0" ]; then
		return 6
	fi

	return 0

}

tape_format () {

	mkdir -p ${tapedrivedir}/Blank
	cd ${tapedrivedir}/Blank
	$TARCREATECMD $tarname .

	if [ "$?" -ne 0 ]; then
		return 12
	fi

	return 0

}

tape_backup () {

if [ "$numparams" -lt 6 ]; then
	#echo "Not enough parameters"
	exit 10
fi

	if [ "$partition" -lt "10" ]; then
		partition="0${partition}"
	fi

	if [ "$partition" -gt 14 ]; then
		return 13
	fi

	if [ ! -e ${tapedrivepath} ]; then
		return 13
	fi

	backuppath="$mountdir/${partition}${discname}"
	backupsource="$fsdir/$discdirname"

	#echo $backuppath
	#echo $backupsource

	cd ${tapedrivepath}

	if [ "$?" -ne "0" ]; then
		return 13
	fi

	rm -rf ${partition}* # Delete any existing partition

	mkdir ${backuppath}

	if [ "$?" -ne "0" ]; then
		return 15
	fi

	touch ${mountdir}/.busy

	(cd $backupsource ; $TARCREATECMD - . ) | (cd $backuppath ; $TAREXTRACTCMD - )

	if [ "$?" -ne "0" ]; then
		rm ${mountdir}/.busy
		return 16
	fi

	rm ${mountdir}/.busy

	return 0

	
}

# We don't implement restore - SYST users can mount the tape and copy what they want.

case "$cmd" in
	"mount")
		tape_mount $tapedir $tarname $mountdir $tapedrivepath 
		result=$?
		;;
	"umount")
		tape_umount $tapedir $tarname $mountdir $tapedrivepath
		result=$?
		;;
	"format")
		tape_format $tapedir $tapename $tarname $mountdir
		result=$?
		;;
	"backup")
		if [ "$#" -lt 5 ]; then
			#echo "Not enough parameters"
			exit 10
		fi

		tape_backup $tapedrivepath $tarname $partition $discname
		result=$?
		;;
	"drivestate")
		if [ "$#" -lt 4 ]; then
			exit 10
		fi

		tape_drivestate
		result=$?
		;;
	*)
		#echo "Unknown tape command $cmd" 
		result=3 ;;
esac

exit $result

