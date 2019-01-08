OBJ := tcpForward
CC := gcc
STRIP := strip
CFLAGS := -O2 -Wall -pthread
#如果是安卓编译
ifeq ($(ANDROID_DATA),/data)
	CFLAGS := -O2 -pie -Wall
	SHELL = /system/bin/sh
endif


all : tcpForward.o acl.o conf.o limitSpeed.o
	$(CC) $(CFLAGS) $(DEFS) -o $(OBJ) $^
	$(STRIP) $(OBJ)
	-chmod 777 $(OBJ) 2>&-

.c.o : 
	$(CC) $(CFLAGS) $(DEFS) -c $<

clean : 
	rm -f *.o
