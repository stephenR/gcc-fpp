CC=./gcc
CFLAGS=-ggdb -O0 -Wl,-z,relro,-z,now -Wall -Wextra

all: main main.static

libfpprotect.o: libfpprotect.c
	$(CC) $(CFLAGS) -fPIC -c $<

libfpprotect.so: libfpprotect.o
	$(CC) -nostdlib -shared $(CFLAGS) -o $@ $^

libfpprotect.a: libfpprotect.o
	ar rcs $@ $^

main: main.c libfpprotect.so
	$(CC) -o $@ -ffp-protect $(CFLAGS) $< -lfpprotect

main.static: main.c libfpprotect.a
	$(CC) -o $@ -ffp-protect $(CFLAGS) $< -lfpprotect -static

clean:
	- rm libfpprotect.so libfpprotect.a libfpprotect.o main
