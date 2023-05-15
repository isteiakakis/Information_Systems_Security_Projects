CC=gcc
CFLAGS=-g3 -Wall
CLIBS=-L/usr/lib -lssl -lcrypto

BINS=server client

all: $(BINS)
	
%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(CLIBS)

clean:
	$(RM) $(BINS)
