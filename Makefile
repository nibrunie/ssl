CFLAGS:=-Wall -Werror -g
CFLAGS+= -O2
LDFLAGS:=-g
LDLIBS:=-lssl -lcrypto

all: ssl

ssl: ssl.c

clean:
	$(RM) ssl

test: ssl
	./ssl 55555 </dev/zero >/dev/null &
	sleep 1
	dd if=/dev/zero count=1000000 bs=300 | ncat --ssl 127.0.0.1 55555 | dd of=/dev/null bs=300

test-nossl:
	ncat -l 55555 </dev/zero >/dev/null &
	sleep 1
	dd if=/dev/zero count=10000000 bs=300 | ncat localhost 55555 | dd of=/dev/null bs=300

.PHONY: all clean test test-nossl
