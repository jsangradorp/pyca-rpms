
SOURCESDIR=./pyca-20031118
INSTALLDIR=dest/pyca-root

DIRS=/etc/pyca \
     /etc/cron.hourly \
     /etc/httpd/conf.d \
     /usr/share/doc \
     /usr/bin \
     /usr/sbin \
     /usr/local/pyca/pylib \
     /usr/share/pyca \
     /usr/share/doc/pyca \
     /var/lib/pyca/certs \

.PHONY: rpm
rpm:
	rpmbuild --rcfile=rpm/rpmrc -bb rpm/pyca.spec

mkdirs:
	for dir in ${DIRS} ; do mkdir -p ${INSTALLDIR}$$dir ; done

startinstalling:
	echo 'Installing'

install: startinstalling mkdirs copyfiles doconfig
	@echo 'Done installing'

startcopying:
	@echo 'Copying files'

copyfiles: startcopying copyweb copybin copydoc copylib copyconf
	cp scripts/new-ca.sh ${INSTALLDIR}/usr/sbin
	@echo 'Done copying'

copyweb: mkdirs
	cp -rf ${SOURCESDIR}/cgi-bin/* ${INSTALLDIR}/usr/share/pyca

copybin: mkdirs
	cp -rf ${SOURCESDIR}/bin/* ${INSTALLDIR}/usr/bin
	cp -rf ${SOURCESDIR}/sbin/* ${INSTALLDIR}/usr/sbin

copydoc: mkdirs
	-cp -rf ${SOURCESDIR}/doc/* ${INSTALLDIR}/usr/share/doc/pyca
	cp -rf ${SOURCESDIR}/htdocs ${INSTALLDIR}/usr/share/doc/pyca
	cp -rf ${SOURCESDIR}/help ${INSTALLDIR}/usr/share/pyca

copylib: mkdirs
	cp -rf ${SOURCESDIR}/pylib/* ${INSTALLDIR}/usr/local/pyca/pylib

copyconf: mkdirs
	cp -rf ${SOURCESDIR}/conf/* ${INSTALLDIR}/etc/pyca

doconfig:
	# First apache config
	echo 'ScriptAlias /pyca /usr/share/pyca' > ${INSTALLDIR}/etc/httpd/conf.d/pyca
	# Now cron config
	echo "ca-cycle-priv.py --config=/etc/pyca/openssl.cnf" > ${INSTALLDIR}/etc/cron.hourly/pyca
	echo "ca-cycle-pub.py --config=/etc/pyca/openssl.cnf" >> ${INSTALLDIR}/etc/cron.hourly/pyca
	# And fix pyca config itself
	sed -i -e 's,/etc/openssl,/etc/pyca,g' ${INSTALLDIR}/usr/share/pyca/pycacnf.py
	# next is to avoid a nasty warning
	sed -i -e '1i# vim: set fileencoding=latin-1 :' ${INSTALLDIR}/usr/local/pyca/pylib/openssl/cnf.py
	# and configure
	sed -i -e 's,/etc/openssl,/etc/pyca,g' ${INSTALLDIR}/etc/pyca/openssl.cnf
	sed -i -e 's,/usr/local,/var/lib/pyca,g' ${INSTALLDIR}/etc/pyca/openssl.cnf
	sed -i -e 's,\(userWWWRun *= *\)wwwrun,\1apache,' ${INSTALLDIR}/etc/pyca/openssl.cnf
	sed -i -e 's,^#ErrorLog,ErrorLog,' ${INSTALLDIR}/etc/pyca/openssl.cnf
	sed -i -e 's,@ms.inka.de,,' ${INSTALLDIR}/etc/pyca/openssl.cnf

