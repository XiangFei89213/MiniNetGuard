cc = gcc
CFLAGS = -Wall -Iinclude
LIBS = -Inetfilter_queue Ibloom

SRC = src/main.c src/config_parser.c src/blacklist.c src/packet_filter.c src/bloom_wrapper.c
OBJ = main.o config_parser.o blacklist.o packet_filter.o bloom_wrapper.o

all: firewall

firewall: $(SRC)
	$(CC) $(CFLAGS) -o firewall $(SRC) $(LIBS)

clean:
	rm -f firewall *-o