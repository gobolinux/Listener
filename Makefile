PREFIX = /usr
SYSCONFDIR = /etc

all:
	make -C src

clean:
	make -C src clean
	rm -f bin/listener

install:
	mkdir -p $(SYSCONFDIR) $(PREFIX)/bin $(PREFIX)/share
	cp -v bin/listener $(PREFIX)/bin
	cp -vr share/Listener $(PREFIX)/share
	cp -v config/listener.conf $(SYSCONFDIR)
