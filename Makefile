
INSTALLDIR=dest/pyca-root

DIRS=/etc/pyca \
     /etc/cron.hourly \
     /etc/httpd/conf.d \
     /usr/share/doc \
     /usr/bin \
     /usr/sbin \
     /usr/lib/python2.4/site-packages/pycalib \
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
	echo 'Done installing'

startcopying:
	echo 'Copying files'

copyfiles: startcopying copyweb copybin copydoc copylib copyconf
	echo 'Done copying'

copyweb: mkdirs
	cp -rf cgi-bin/* ${INSTALLDIR}/usr/share/pyca

copybin: mkdirs
	cp -rf bin/* ${INSTALLDIR}/usr/bin
	cp -rf sbin/* ${INSTALLDIR}/usr/sbin

copydoc: mkdirs
	-cp -rf doc/* ${INSTALLDIR}/usr/share/doc/pyca
	cp -rf htdocs ${INSTALLDIR}/usr/share/doc/pyca
	cp -rf help ${INSTALLDIR}/usr/share/pyca

copylib: mkdirs
	cp -rf pylib/* ${INSTALLDIR}/usr/lib/python2.4/site-packages/pycalib

copyconf: mkdirs
	cp -rf conf/* ${INSTALLDIR}/etc/pyca

doconfig:
	echo "sljlkd" > ${INSTALLDIR}/etc/httpd/conf.d/pyca
	echo "kjhkh" > ${INSTALLDIR}/etc/cron.hourly/pyca
	echo Updating config.

