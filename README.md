# sample-net-firewall
A sample net firewall

This is simple network firewall writed by Yonggang Guo <hero.gariker@gmail.com>.

# Step to set kernel:
## Step 1:
cp ipv4_hunter.c net/ipv4/netfilter/ipv4_hunter.c
cp ipv4_hunter.h cp include/net/ipv4_hunter.h

## step 2:
vim net/ipv4/netfilter/Makefile

and add the content as followed:
obj-y += ipv4_hunter.o

## step 3:
compile kernel source.

## step 4:
fastboot the kernel to device.


# Step to set arguments:
Please use the tool inet_filter I supported(which is in the branch inet_filter).
