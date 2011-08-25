#!/bin/bash
read -e -r -p "ISO country code: " COUNTRY_CODE
read -e -r -p "State/Province Name: " STATE_OR_PROVINCE
read -e -r -p "Location: " LOCATION
read -e -r -p "Organization: " ORGANIZATION
read -e -r -p "Organizational Unit Name: " ORGANIZATIONAL_UNIT
read -e -r -p "hostname (for the public URLs): " URL_HOSTNAME
read -e -r -p "SMTP relay host (can be localhost): " SMTP_RELAY_HOST
read -e -r -p "E-mail address of the CA administrator: " CAADMIN_EMAIL
read -e -r -p "E-mail address for certreq dialogue: " DIALOGUE_EMAIL
read -e -r -p "Mail server FQDN to poll certreq dialogue messages: " DIALOGUE_SERVER
read -e -r -p "Mail server protocol for certreq dialogue messages (eg. \"imap\", \"pop3\"): " DIALOGUE_PROTO
read -e -r -p "Mail server for certreq dialogue messages ssl option (\"ssl\" or empty): " DIALOGUE_SSL
read -e -r -p "Mail server user name for certreq dialogue: " DIALOGUE_USER
read -e -s -r -p "Mail server user password for certreq dialogue: " DIALOGUE_PASS

sed -i -e "s#\\(countryName_default[ \\t]*=[ \\t]*\\).*#\\1$COUNTRY_CODE#g" /etc/pyca/*
sed -i -e "s#\\(stateOrProvinceName_default[ \\t]*=[ \\t]*\\).*#\\1$STATE_OR_PROVINCE#g" /etc/pyca/*
sed -i -e "s#\\(localityName_default[ \\t]*=[ \\t]*\\).*#\\1$LOCATION#g" /etc/pyca/*
sed -i -e "s#\\(organizationName_default[ \\t]*=[ \\t]*\\).*#\\1$ORGANIZATION#g" /etc/pyca/*
sed -i -e "s#\\(organizationalUnitName_default[ \\t]*=[ \\t]*\\).*#\\1$ORGANIZATIONAL_UNIT#g" /etc/pyca/*
sed -i -e "s#\\(commonName_default[ \\t]*=[ \\t]*\\)\"\\(.*\\)[ \\t]\\+TestCA\"#\\1\"$ORGANIZATION \\2 CA\"#g" /etc/pyca/*
sed -i -e "s#localhost#$URL_HOSTNAME#g" /etc/pyca/*
sed -i -e "s#^MailRelay = .*#MailRelay = $SMTP_RELAY_HOST#g" /etc/pyca/*
sed -i -e "s#^caCertReqMailAdr = .*#caCertReqMailAdr = $DIALOGUE_EMAIL#g" /etc/pyca/*
sed -i -e "s#^caAdminMailAdr = .*#caAdminMailAdr = $CAADMIN_EMAIL#g" /etc/pyca/*
sed -i -e "s#^organization[ \\t]*=[ \\t]*.*#organization = \"$ORGANIZATION\"#g" /etc/pyca/*


# Install fetchmail and set this $HOME/.fetchmailrc for caadmin user
echo "poll $DIALOGUE_SERVER proto $DIALOGUE_PROTO user $DIALOGUE_USER password $DIALOGUE_PASS mda \"/usr/sbin/ca-certreq-mail.py --config /etc/pyca/openssl.cnf\" $DIALOGUE_SSL keep" > /home/caadmin/.fetchmailrc
chown caadmin:caadmin /home/caadmin/.fetchmailrc
chmod 0600 /home/caadmin/.fetchmailrc
# Create the CAs based on the previous configuration
/usr/sbin/ca-make.py --config=/etc/pyca/openssl.cnf
# Next is because caadmin is the mail delivery agent daemon itself, so it wouldn't be allowed read access
chmod u+r /var/lib/pyca/myCA/EmailCerts/newreqs \
	/var/lib/pyca/myCA/ServerCerts/newreqs \
	/var/lib/pyca/myCA/CodeSigning/newreqs \
	/var/lib/pyca/myCA/AuthCerts/newreqs

