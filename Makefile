
obj-m := sig_monitor_base.o sig_monitor.o dump_sighand.o

#KDIR := /lib/modules/$(bash uname -r)/build
KDIR := /usr/src/kernels/3.10.0-862.9.1.el7.x86_64
CURR := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(CURR) modules
clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(CURR) clean
