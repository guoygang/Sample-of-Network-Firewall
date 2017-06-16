# sample of network firewall
A sample network firewall (# Test on Pixel phone)

This is simple network firewall writed by Yonggang Guo \<hero.gariker@gmail.com\>.

## Step to set kernel:
Step 1:<br>
cp ipv4_hunter.c net/ipv4/netfilter/ipv4_hunter.c<br>
cp ipv4_hunter.h cp include/net/ipv4_hunter.h

step 2:<br>
vim net/ipv4/netfilter/Makefile<br>
Add the content as followed:<br>
obj-y += ipv4_hunter.o

step 3:<br>
Compile kernel source & fastboot the kernel to device.



## Step to set arguments from userspace to kernel:
Please use the tool inet_filter I supported(which is in the branch inet_filter).
