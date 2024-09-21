.PHONY: first all clean mksh

first: all

all: dropbear/dropbear

clean:
	@make -C dropbear/ clean

mksh:
	@cd mksh && MAKE_LIB=y CFLAGS="-DMKSH_SHARED" ./Build.sh

dropbear/dropbear:
	@cd dropbear && ./configure
	@make -C dropbear/ PROGRAMS=dropbear