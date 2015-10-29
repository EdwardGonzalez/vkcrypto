CC?=gcc
CFLAGS?=-fPIC -Wall -Werror -Wextra
LIBDIR?=/usr/local/lib/
INCLUDEDIR?=/usr/local/include/

build:
	$(CC) $(CFLAGS) -c vkcrypto.c
	$(CC) -shared -o libvkcrypto.so vkcrypto.o -lscrypt -lcrypto
install:
	install -c -m 755 libvkcrypto.so $(LIBDIR)
	install -c -m 755 vkcrypto.h $(INCLUDEDIR)
clean:
	rm libvkcrypto.so vkcrypto.o
