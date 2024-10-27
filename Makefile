.PHONY: first all clean mksh forkless dropbear dummy

first: all

all: forkless

clean:
	@make -C dropbear/ clean

forkless: dropbear mksh
	gcc -g -rdynamic -Isrc/ src/tvm.c src/main.c -o forkless -L . -ldropbear -lmksh -lz -lpthread -lutil -pie

test:
	gcc -g -rdynamic -Isrc/ src/tvm.c src/test_tvm.c -o test_tvm -lpthread -pie

mksh:
	if [ -f mksh/Rebuild.sh ]; then cd mksh && sh ./Rebuild.sh; else cd mksh && CFLAGS="-g -rdynamic -I$(realpath .) -DMKSH_FORKLESS=1" sh ./Build.sh; fi
	objcopy --redefine-sym main=mksh_main mksh/main.o
	find mksh/ -type f -name '*.o' | xargs ar rcs libmksh.a

dropbear: dummy
	if [ ! -f dropbear/Makefile ]; then cd dropbear && CFLAGS="-g -rdynamic -I$(realpath .)" ./configure; fi
	make -C dropbear/ PROGRAMS="dropbear scp" MULTI=1 LDFLAGS="/tmp/dummy.o -o /tmp/dummy.out && echo"
	find dropbear/ -type f -name '*.o' | xargs ar rcs libdropbear.a

dummy:
	@gcc src/dummy/dummy.c -c -o /tmp/dummy.o