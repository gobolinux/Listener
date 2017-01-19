CC = gcc
SYSCONFDIR = /etc
CFLAGS  = -I. -DSYSCONFDIR=\"$(SYSCONFDIR)\" -Wall -g
LDFLAGS = -lpthread

all: listener

clean:
	-rm -f *.o *~

listener: listener.o rules.o
	$(CC) listener.o rules.o -o listener $(LDFLAGS)
	mkdir -p ../bin
	cp listener ../bin

%.o: %.c
	$(CC) -c $< $(CFLAGS)
