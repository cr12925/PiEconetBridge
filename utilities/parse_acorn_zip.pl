#!/usr/bin/perl
#
# Acorn ZIP files typically have extended information in them that
# preserves the Load/Exec address (amongst others).  When extracting
# these Zip files on a Unix machine that information is lost.
#
# This program will parse a zip file and create a shell script (on stdout)
# that will build ".inf" files that are compatible with the PiEconetBridge
#
# We only extra the load/exec addresses from the zip file.
# We hard code the owner of the file as SYST (user 0).  Directories are
# given permission WR/ and files given permission LWR/R.
#
# So the idea is you can unzip the Zip file and then run this program
# to generate a script that would set the attributes
#
# e.g
#  cd /econet/0System
#  mkdir ArthurLib
#  cd ArthurLib
#  unzip ..../NetLibA.zip
#  ..../parse_acorn_zip.pl ..../NetLibA.zip | bash

use warnings;
use strict;

my $name=$ARGV[0];

die "$0 filename\n" unless $name;

open(my $fh,"<$name") or die "$name: $!\n";

my @results;

while(1)
{

  # Get the header.  At least we hope it's the header

  sysread($fh, my $header, 4);

  # This is the start of the central directory, which is after all the
  # data, and isn't needed.  So we can stop here
  last if $header eq "PK\1\2";

  # This better match
  die "Section does start PK<03><04>: $header\n" unless $header eq "PK\3\4";

  # This information is in the ZIP header.  We don't need it all
  sysread($fh, my $version, 2);
  sysread($fh, my $flag, 2);
  sysread($fh, my $method, 2);
  sysread($fh, my $time, 2);
  sysread($fh, my $date, 2);
  sysread($fh, my $crc, 4);
  sysread($fh, my $comp_size, 4); $comp_size=unpack("L", $comp_size);
  sysread($fh, my $size, 4); $size=unpack("L", $size);
  sysread($fh, my $namelen, 2); $namelen=unpack("S",$namelen);
  sysread($fh, my $extralen, 2); $extralen=unpack("S",$extralen);

  # Now we can get the filename and any extra header data
  sysread($fh, my $filename, $namelen);
  sysread($fh, my $extra, $extralen);

  # Skip the compressed data.  We don't care.
  seek($fh,$comp_size, 1);

  # Check if this has Acorn extended information
  next if $extralen<8;
  next unless substr($extra,0,2) eq "AC";
  next unless substr($extra,4,4) eq "ARC0";  

  my $load=unpack("L",substr($extra,8,4));
  my $exec=unpack("L",substr($extra,12,4));
  
  my $perm=0x17;  # LWR/R
  $perm=3 if $filename=~s/\/$//;  # WR for directories
  push(@results,sprintf("echo -n %x %08x %08x %02x > %s.inf",0,$load,$exec,$perm,$filename));
}

print "#!/bin/bash\n";
foreach (@results) { print "$_\n"; }
