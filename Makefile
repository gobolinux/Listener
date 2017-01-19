PREFIX = /usr
SYSCONFDIR = /etc

all:
	make -C src

clean:
	make -C src clean
	rm -rf bin Resources/FileHash* *~

install:
	mkdir -p $(SYSCONFDIR) $(PREFIX)/bin
	cp bin/listener $(PREFIX)/bin
	cp config/listener.conf $(SYSCONFDIR)
