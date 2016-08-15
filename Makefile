OPENSSL11?=0
OPENSSL11_DIR:=../../openssl/install

PORT?=55555
CIPHER?=AES256-GCM-SHA384
DURATION?=10

CFLAGS:=-Wall -Werror -g -pthread
CFLAGS+= -O2
LDFLAGS:=-g -pthread
LDLIBS:=-lssl -lcrypto

ifneq ($(OPENSSL11), 0)
OPENSSL11_BINDIR:=$(OPENSSL11_DIR)/bin
OPENSSL11_LIBDIR:=$(OPENSSL11_DIR)/lib
CFLAGS+=-I ../../openssl/install/include -Wno-deprecated-declarations
LDLIBS+=-L$(OPENSSL11_LIBDIR)
export PATH:=$(OPENSSL11_BINDIR):$(PATH)
export LD_LIBRARY_PATH:=$(OPENSSL11_LIBDIR):$(LD_LIBRARY_PATH)
endif

all: server client

server: server.c

client: client.c

clean:
	$(RM) server client

test: server client
	./server $(PORT) $(CIPHER) &
	sleep 0.5
	./client 127.0.0.1 $(PORT) $(CIPHER) < /dev/zero > /dev/null &
	./client 127.0.0.1 $(PORT) $(CIPHER) < /dev/zero > /dev/null &
	sleep $(DURATION)
	-pkill client
	-pkill server

.PHONY: all clean test
