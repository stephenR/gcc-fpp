CC=gcc
CFLAGS=-ggdb -O0

libfpprotect.so: CFLAGS+=-fPIC -shared
libfpprotect.so: libfpprotect.o
	$(CC) $(CFLAGS) -o $@ $^
