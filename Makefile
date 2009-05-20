CC = gcc
LIBS = -lpcap
CFLAGS = -Wall -g -O1
ZDCClinet	: md5.o zdclient.o
	$(CC) $(LIBS) -o $@ md5.o zdclient.o

md5.o	: md5.c md5.h
	$(CC) $(CFLAGS) -c $<

zdclient.o : zdclient.c
	$(CC) $(CFLAGS) -c $<
	
clean :
	rm -v *.o ZDCClinet
