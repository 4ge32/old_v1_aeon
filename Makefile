#
# Makefile for the linux NOVA filesystem routines.
#

obj-m += aeon.o

aeon-y := super.o balloc.o inode.o file.o namei.o mprotect.o dir.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean
	rm -v balloc.o.ur-safe
	rm -v mprotect.o.ur-safe
