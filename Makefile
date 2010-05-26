PREFIX=/usr/local
SBINDIR=${PREFIX}/sbin
CONFDIR=${PREFIX}/etc/sipade
LOGDIR=/var/log/sipade/

build:
	@echo "You need libpq-dev and libpyaml-dev to compile SipADE."
	${MAKE} -C src/

clean:
	${MAKE} -C src/ $@

install: 
	# binary
	install -d ${DESTDIR}${SBINDIR}
	install -m 755 -o root -g root src/sipade ${DESTDIR}${SBINDIR}/sipade
	# config
	install -d ${DESTDIR}${CONFDIR}
	install -m 644 -o root -g root conf/sipade.yaml ${DESTDIR}${CONFDIR}/

