obj-m                := mlkm_shield.o
mlkm_shield-objs     := bwlist.o config.o hooks.o module.o safemem.o shield.o symbols.o threats.o x86.o
EXTRA_CFLAGS         := -DDEBUG -I$(PWD)/include
src                  := $(PWD)/src
obj                  := $(PWD)/obj

CC   = gcc -Wall
KDIR = /lib/modules/$(shell uname -r)/build
PWD  = $(shell pwd)
MODN = mlkm_shield
MNTD = $(shell /usr/bin/lsmod | /usr/bin/grep $(MODN))

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
install:
	/sbin/insmod $(MODN).ko

.PHONY: clean clean-all

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

clean-all: clean
ifneq ($(MNTD),)
	/sbin/rmmod $(MODN)
endif

