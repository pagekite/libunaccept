
CC=gcc
CFLAGS=-fPIC
LDFLAGS=-shared -Wl,-soname,libunaccept.so
LDLIBS=-ldl

default: libunaccept.so

%.so: %.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

install: libunaccept.so
	install -s libunaccept.so /usr/local/lib

clean:
	rm -f *.so *.o
