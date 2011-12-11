
CC=gcc
CFLAGS=-fPIC
LDFLAGS=-shared -Wl,-soname,libunaccept.so
LDLIBS=-ldl

default: libunaccept.so

%.so: %.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

install: libunaccept.so
	install -s libunaccept.so /usr/local/lib
	mkdir -p /etc/libunaccept.d
	touch /etc/libunaccept.d/default.rc

uninstall:
	rm -f /usr/local/lib/libunaccept.so

clean:
	rm -f *.so *.o
