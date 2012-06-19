CFLAGS+=-Wall -Wextra -std=c99

ifeq ($(DEBUG),1)
  CFLAGS+=-ggdb
else
  CFLAGS+=-O2 -funroll-loops
endif

bn: bn.o
	$(CC) -o $@ $<

clean:
	rm bn bn.o
