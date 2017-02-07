PREFIX = /usr
SYSCONFDIR = /etc

all:
	make -C src

clean:
	make -C src clean
	rm -f bin/listener

install:
	mkdir -p $(SYSCONFDIR) $(PREFIX)/bin $(PREFIX)/share/Listener
	cp -v bin/listener $(PREFIX)/bin
	cp -vr share/Listener/* $(PREFIX)/share/Listener
	cp -v config/listener.conf $(SYSCONFDIR)
