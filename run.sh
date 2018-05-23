#!/bin/sh

FS="aeon"
DEV=/dev/pmem0

run () {
  sudo umount mnt
  sudo rmmod $FS
  make
  sudo insmod $FS.ko
  sudo mount -t $FS -o init $DEV /mnt
  dmesg
}

clean () {
  sudo umount mnt
  sudo rmmod $FS
  make clean
}

fs_test() {
	echo $FS
}

case "$1" in
  clean)
    clean
    ;;
  test)
    fs_test
    ;;
  *)
    run
    ;;
esac
exit 0
