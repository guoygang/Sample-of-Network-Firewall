# sample-net-firewall
A sample net firewall

This is simple firewall writed by Yonggang Guo.

Date: 2017.06.16

## Step to set kernel:
# =================================================
## Step 1:
# cp ipv4_hunter.c net/ipv4/netfilter/ipv4_hunter.c
# ipv4_hunter.h cp include/net/ipv4_hunter.h

## step 2:
# vim net/ipv4/netfilter/Makefile

and add the content as followed:
# obj-y += ipv4_hunter.o

## step 3:
compile kernel source.

## step 4:
fastboot the kernel to device.
# ==================================================


## Step to set arguments:
Please use the tool inet_filter I supported.
