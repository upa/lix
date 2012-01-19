KERNELSRCDIR = /lib/modules/$(shell uname -r)/build
BUILD_DIR := $(shell pwd)

obj-m := lisp.o

lisp-objs := main.o netdev.o netlink.o etr.o itr.o mtu.o encapsulate.o utils.o route.o

all:
	make -C $(KERNELSRCDIR) M=$(BUILD_DIR) modules
	rm -f *.o
	rm -f *.mod.c
	rm -f *~

