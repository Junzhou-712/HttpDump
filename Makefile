TARGET	:= httpdump
CC	:= gcc

obj-m	+= $(TARGET).o
$(TARGET)-objs	+= main.o callback.o head.o packetprocess.o

KERNEL_DIR	?= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)
all:
    make -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules

.PHONY:clean
clean:
	rm -rf *.o *.ko *.ko.* *.mod.*