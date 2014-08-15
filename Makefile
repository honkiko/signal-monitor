
obj-m := sig_monitor_base.o sig_monitor.o dump_sighand.o

#KDIR := /lib/modules/$(shell uname -r)/build
KDIR := /data/home/zhiguo/tlinux-2.6.32.43/kernel-tlinux-2.6.32.43
CURR := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(CURR) modules
clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(CURR) clean
