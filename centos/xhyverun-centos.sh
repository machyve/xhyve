#!/bin/bash
KERNEL="vmlinuz-3.10.0-957.el7.x86_64"
INITRD="initramfs-3.10.0-957.el7.x86_64.img"
CMDLINE="root=UUID=ad6a4283-c0a1-445a-9b56-629d9aff7aba ro crashkernel=auto acpi=off console=ttyS0 LANG=en_US.UTF-8"
MEM="-m 1G"
#SMP = "- C 2" # number of processors
NET="-s 2:0,virtio-net"
IMG_HDD="-s 4,virtio-blk,hdd.img"
PCI_DEV="-s 0:0,hostbridge -s 31,lpc"
LPC_DEV="-l com1,stdio"
UUID="-U 0C1F891D-7C67-4391-8C22-7A31F27EF8A3"
xhyve $MEM $SMP $PCI_DEV $LPC_DEV $NET $IMG_CD $IMG_HDD $UUID -f kexec,$KERNEL,$INITRD,"$CMDLINE"
