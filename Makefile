.PHONY: first all clean mksh forkless dropbear dummy toybox

first: all

all: forkless

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Linux)
	LDFLAGS += -lm -pie
endif
ifeq ($(UNAME_S), Darwin)
	LDFLAGS +=
endif

clean:
	@make -C dropbear/ clean || true
	@make -C toybox/ clean || true
	@rm dropbear/Makefile || true
	@rm mksh/Rebuild.sh || true

forkless: dropbear mksh toybox
	gcc -g -rdynamic -I. tvm.c main.c -o forkless -L . -ldropbear -lmksh -ltoybox -lz -lpthread -lutil $(LDFLAGS)

test:
	gcc -g -rdynamic -I. tvm.c test_tvm.c -o test_tvm -lpthread $(LDFLAGS)

mksh:
	if [ -f mksh/Rebuild.sh ]; then cd mksh && sh ./Rebuild.sh; else cd mksh && CFLAGS="-g -I$(realpath .) -DMKSH_FORKLESS=1" sh ./Build.sh; fi
	find mksh/ -type f -name '*.o' | xargs ar rcs libmksh.a

dropbear: dummy
	if [ ! -f dropbear/Makefile ]; then cd dropbear && CFLAGS="-g -I$(realpath .)" ./configure; fi
	make -C dropbear/ PROGRAMS="dropbear scp" MULTI=1 LDFLAGS="/tmp/dummy.o -o /tmp/dummy.out && echo"
	find dropbear/ -type f -name '*.o' | xargs ar rcs libdropbear.a

toybox:
	CFLAGS="-g -I$(realpath .) -DTOYBOX_FORKLESS=1" V=1 make -C toybox
	find toybox/ -type f -name '*.o' | xargs ar rcs libtoybox.a

dummy:
	@gcc dummy/dummy.c -c -o /tmp/dummy.o