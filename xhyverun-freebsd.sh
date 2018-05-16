#!/bin/sh

BOOTVOLUME="<path of FreeBSD iso>"
IMG="<path of disk image for FreeBSD>"

build/xhyve \
    -A \
    -m 2G \
    -c 2 \
    -s 0:0,hostbridge \
    -s 2:0,virtio-net \
    -s 3:0,ahci-cd,$BOOTVOLUME \
    -s 4:0,virtio-blk,$IMG \
    -s 31,lpc \
    -l com1,stdio \
    -f fbsd,test/userboot.so,$BOOTVOLUME,""
