#
# Makefile for the linux NOVA filesystem routines.
#

obj-m += aeon.o

aeon-y := super.o balloc.o inode.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean