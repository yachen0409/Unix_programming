CC = gcc
CFLAGS = -shared -fPIC -ldl

all: sandbox.so

sandbox.so: sandbox.c
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	rm -f sandbox.so
