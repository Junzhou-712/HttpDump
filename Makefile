TARGET	:= httpdump
CC	:= gcc
SRC	:= /usr/src/kernels/4.18.0-348.7.1.el8_5.aarch64

obj-m	:= $(TARGET).o
ccflags-y	:= -I$(SRC)/include
$(TARGET)-objs	+= main.o callback.o head.o packetprocess.o

KERNEL_DIR	?= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)
all:
    make -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules

.PHONY:clean
clean:
	rm -rf *.o *.ko *.ko.* *.mod.*