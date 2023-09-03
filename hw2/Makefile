CC = gcc
CFLAGS = -lcapstone

all: sdb

sdb: sdb.c
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	rm -f sdb
