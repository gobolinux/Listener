PREFIX = /usr
SYSCONFDIR = /etc

all:
	make -C src

clean:
	make -C src clean
	rm -rf bin Resources/FileHash* *~

install:
	mkdir -p $(SYSCONFDIR) $(PREFIX)
	cp -r bin $(PREFIX)
	cp -r share $(PREFIX)
	cp config/listener.conf $(SYSCONFDIR)
