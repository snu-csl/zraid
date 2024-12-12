obj-m += zraid.o
zraid-objs := main.o pp.o util.o nvme_util.o iosub.o comph.o zrwam.o recovery.o
ccflags-y := -std=gnu11 -Wimplicit-fallthrough=0 -O3 -w $(CFLAGS)

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) KBUILD_EXTRA_SYMBOLS=$(shell readlink -f ../nvme/Module.symvers) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
