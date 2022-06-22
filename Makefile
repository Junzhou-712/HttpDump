TARGET	:= httpdump
CC	:= gcc
SRC	:= /usr/src/kernels/4.18.0-348.7.1.el8_5.aarch64
INCLUDES	:= main.c callback.c
OBJS 	:= main.o callback.o
CFLAGS		:= -lpcap

obj-m	:= $(TARGET).o
ccflags-y	:= -I$(SRC)/include
$(TARGET)-objs	+= main.o callback.o head.o packetprocess.o

KERNEL_DIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)
all:
	$(CC) $(INCLUDES) -c 
	$(CC) $(OBJS) -o $(TARGET) $(CFLAGS)
.PHONY:clean
clean:
	rm -rf *.o *.ko *.ko.* *.mod.* *.h.gch