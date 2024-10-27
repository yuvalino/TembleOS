.PHONY: first all clean mksh forkless dropbear dummy

first: all

all: forkless

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Linux)
	LDFLAGS += -pie
endif
ifeq ($(UNAME_S), Darwin)
	LDFLAGS +=
endif

clean:
	@make -C dropbear/ clean
	@rm dropbear/Makefile
	@rm mksh/Rebuild.sh

forkless: dropbear mksh
	gcc -g -rdynamic -I. tvm.c main.c -o forkless -L . -ldropbear -lmksh -lz -lpthread -lutil $(LDFLAGS)

test:
	gcc -g -rdynamic -I. tvm.c test_tvm.c -o test_tvm -lpthread $(LDFLAGS)

mksh:
	if [ -f mksh/Rebuild.sh ]; then cd mksh && sh ./Rebuild.sh; else cd mksh && CFLAGS="-g -I$(realpath .) -DMKSH_FORKLESS=1" sh ./Build.sh; fi
	find mksh/ -type f -name '*.o' | xargs ar rcs libmksh.a

dropbear: dummy
	if [ ! -f dropbear/Makefile ]; then cd dropbear && CFLAGS="-g -I$(realpath .)" ./configure; fi
	make -C dropbear/ PROGRAMS="dropbear scp" MULTI=1 LDFLAGS="/tmp/dummy.o -o /tmp/dummy.out && echo"
	find dropbear/ -type f -name '*.o' | xargs ar rcs libdropbear.a

dummy:
	@gcc dummy/dummy.c -c -o /tmp/dummy.o