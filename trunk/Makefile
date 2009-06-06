CC = gcc
LIBS = -lpcap
CFLAGS = -Wall -g

.PHONY: all
all: zdclient

zdclient	: md5.o zdclient.o main.o
	$(CC) $(CFLAGS) -o $@ md5.o zdclient.o main.o $(LIBS)

main.o	: main.c
	$(CC) $(CFLAGS) -c $<

md5.o	: md5.c md5.h
	$(CC) $(CFLAGS) -c $<

zdclient.o : zdclient.c
	$(CC) $(CFLAGS) -c $<
	
clean :
	rm -v *.o
