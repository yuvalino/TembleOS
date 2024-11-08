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

DROPBEAR 	:= vendor/dropbear
MKSH		:= vendor/mksh
TOYBOX		:= vendor/toybox		

TVM_INCLUDE	:= $(realpath .)

clean:
	@make -C $(DROPBEAR) clean || true
	@make -C $(MKSH) clean || true
	@make -C $(TOYBOX) clean || true
	@rm $(DROPBEAR)/Makefile || true
	@rm $(MKSH)/Rebuild.sh || true

forkless: dropbear mksh toybox
	gcc -g -rdynamic -I. tvm.c main.c -o forkless -L . -ldropbear -lmksh -ltoybox -lz -lpthread -lutil $(LDFLAGS)

test:
	gcc -g -rdynamic -I. tvm.c test_tvm.c -o test_tvm -lpthread $(LDFLAGS)

mksh:
	if [ -f $(MKSH)/Rebuild.sh ]; then cd $(MKSH) && sh ./Rebuild.sh; else cd $(MKSH) && CFLAGS="-g -I$(TVM_INCLUDE) -DMKSH_FORKLESS=1" sh ./Build.sh; fi
	find $(MKSH) -type f -name '*.o' | xargs ar rcs libmksh.a

dropbear: dummy
	if [ ! -f $(DROPBEAR)/Makefile ]; then cd $(DROPBEAR) && CFLAGS="-g -I$(TVM_INCLUDE)" ./configure; fi
	make -C $(DROPBEAR) PROGRAMS="dropbear scp" MULTI=1 LDFLAGS="/tmp/dummy.o -o /tmp/dummy.out && echo"
	find $(DROPBEAR) -type f -name '*.o' | xargs ar rcs libdropbear.a

toybox:
	CFLAGS="-g -I$(TVM_INCLUDE) -DTOYBOX_FORKLESS=1" V=1 make -C $(TOYBOX)
	find $(TOYBOX) -type f -name '*.o' | xargs ar rcs libtoybox.a

dummy:
	@gcc dummy/dummy.c -c -o /tmp/dummy.o