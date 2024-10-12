.PHONY: first all clean mksh forkless dropbear dummy

first: all

all: forkless

clean:
	@make -C dropbear/ clean

forkless: dropbear #mksh
	gcc -I. tvm.c main.c -o forkless -L . -ldropbear -lmksh -lz -lpthread -lutil -pie

test:
	gcc -fno-stack-protector -I. tvm.c test_tvm.c -o test_forkless -lpthread -pie

mksh:
	@if [ -f mksh/Rebuild.sh ]; then cd mksh && sh ./Rebuild.sh; else cd mksh && sh ./Build.sh; fi
	@objcopy --redefine-sym main=mksh_main mksh/main.o
	@ar rcs libmksh.a $(shell find mksh/ -type f -name '*.o')

dropbear: dummy
	@if [ ! -f dropbear/Makefile ]; then cd dropbear && ./configure; fi
	@make -C dropbear/ PROGRAMS="dropbear scp" MULTI=1 CFLAGS="-I$(realpath .)" LDFLAGS="/tmp/dummy.o -o /tmp/dummy.out && echo"
	@ar rcs libdropbear.a $(shell find dropbear/ -type f -name '*.o')

dummy:
	@gcc dummy/dummy.c -c -o /tmp/dummy.o