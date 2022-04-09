obj-m := mlkm_shield.o
CFLAGS_mlkm_shield.o := -DDEBUG

KDIR = /lib/modules/$(shell uname -r)/build
PWD  = $(shell pwd)
MODN  = mlkm_shield
MNTD = $(shell /usr/bin/lsmod | /usr/bin/grep $(MODN))

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
install:
	insmod $(MODN).ko

.PHONY: clean clean-all

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

clean-all: clean
ifneq ($(MNTD),)
	rmmod $(MODN)
endif

