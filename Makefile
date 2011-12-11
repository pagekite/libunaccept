
CC=gcc
CFLAGS=-fPIC
LDFLAGS=-shared -Wl,-soname,libunaccept.so
LDLIBS=-ldl

default: libunaccept.so

%.so: %.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f *.so *.o
