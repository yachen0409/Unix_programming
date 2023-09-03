#/!bin/sh
find . | cpio -H newc -o | bzip2 > ../newrootfs.cpio.bz2

