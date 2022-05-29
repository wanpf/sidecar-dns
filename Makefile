CC = g++
CFLAGS    = -g  
CPPFLAGS        = -g   -std=c++17 -I./src/  

OBJS	= ./sidecar-dns.o ./src/dns_worker.o ./src/sldns/wire2str.o ./src/sldns/rrdef.o ./src/sldns/str2wire.o ./src/sldns/sbuffer.o \
            ./src/sldns/keyraw.o ./src/sldns/parseutil.o ./src/sldns/parse.o ./src/sldns/locks.o ./src/sldns/log.o ./src/sldns/misc.o \
          ./src/sldns/rbtree.o ./src/dns_cache.o ./src/util.o ./src/dns_proxy.o
SOURCE	= ./sidecar-dns.cpp ./src/dns_worker.cpp ./src/sldns/wire2str.c ./src/sldns/rrdef.c ./src/sldns/str2wire.c ./src/sldns/sbuffer.c \
            ./src/sldns/keyraw.c ./src/sldns/parseutil.c ./src/sldns/parse.c ./src/sldns/locks.c ./src/sldns/log.c ./src/sldns/misc.c \
          ./src/sldns/rbtree.c ./src/dns_cache.cpp ./src/util.cpp ./src/dns_proxy.cpp
HEADER	= 
OUT	= sidecar-dns
LFLAGS	 = -lpthread -ldl -lssl -lcrypto

all: sidecar-dns

sidecar-dns: $(OBJS)
	$(CC) -o $@ $^ $(LFLAGS)

%.o: %.c $(HEADER)
	$(CC) -Wno-deprecated -Wno-deprecated-declarations -Wno-error=deprecated-declarations  -c -I./src -o $@ $< 

# clean house
clean:
	rm -f $(OBJS) $(OUT)

