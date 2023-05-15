CC=gcc
CFLAGS=-g3 -Wall -pedantic
CLIBS=-lpcap

BINS=pcap_ex

all: $(BINS)
	
%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(CLIBS)

clean:
	$(RM) $(BINS)
