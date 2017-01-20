CC         = gcc
SYSCONFDIR = /etc
CFLAGS     = -I. -DSYSCONFDIR=\"$(SYSCONFDIR)\" -Wall -g $(shell pkg-config --cflags libssl libcrypto)
LDFLAGS    = -lpthread $(shell pkg-config --libs libssl libcrypto)
OBJS       = $(patsubst %.c,%.o, $(wildcard *.c))

all: listener

clean:
	-rm -f *.o *~ listener

listener: $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)
	mkdir -p ../bin
	cp listener ../bin

%.o: %.c
	$(CC) -c $< $(CFLAGS)
