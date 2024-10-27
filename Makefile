.PHONY: first all clean mksh forkless dropbear dummy

OS_NAME := $(shell uname -s)
ifeq ($(OS_NAME),Linux)
	CROSS_COMPILE ?= ""

	CC ?= $(CROSS_COMPILE)gcc
	AR ?= $(CROSS_COMPILE)ar
	OBJCOPY ?= $(CROSS_COMPILE)objcopy
	HOST_FLAGS ?= -g -rdynamic
else ifeq ($(OS_NAME),Darwin)
	CC=clang
	AR ?= llvm-ar
	OBJCOPY=llvm-objcopy
	HOST_FLAGS=-g -Wl,-export_dynamic
else
	$(error OS not supported!)
endif

INCLUDE_DIR = $(realpath .)/src

first: all

all: forkless

clean:
	@make -C dropbear/ clean

forkless: dropbear mksh
	$(CC) $(HOST_FLAGS) -pie -I$(INCLUDE_DIR) src/tvm.c src/main.c -o forkless -L . -ldropbear -lmksh -lz -lpthread -lutil

test:
	$(CC) $(HOST_FLAGS) -pie -I$(INCLUDE_DIR) src/tvm.c src/test_tvm.c -o test_tvm -lpthread

mksh:
	if [ -f mksh/Rebuild.sh ]; then cd mksh && sh ./Rebuild.sh; else cd mksh && CFLAGS="$(HOST_FLAGS) -I$(INCLUDE_DIR) -DMKSH_FORKLESS=1" sh ./Build.sh; fi
	$(OBJCOPY) --redefine-sym main=mksh_main mksh/main.o
	find mksh/ -type f -name '*.o' | xargs $(AR) rcs libmksh.a

dropbear: dummy
	if [ ! -f dropbear/Makefile ]; then cd dropbear && CFLAGS="$(HOST_FLAGS) -I$(INCLUDE_DIR)" ./configure; fi
	make -C dropbear/ PROGRAMS="dropbear scp" MULTI=1 LDFLAGS="/tmp/dummy.o -o /tmp/dummy.out && echo"
	find dropbear/ -type f -name '*.o' | xargs $(AR) rcs libdropbear.a

dummy:
	@$(CC) src/dummy/dummy.c -c -o /tmp/dummy.o