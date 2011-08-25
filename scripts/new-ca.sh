#!/bin/bash
read -e -p "ISO country code: " COUNTRY_CODE
read -e -p "State/Province Name: " STATE_OR_PROVINCE
read -e -p "Location: " LOCATION
read -e -p "Organization: " ORGANIZATION
read -e -p "Organizational Unit Name: " ORGANIZATIONAL_UNIT
read -e -p "hostname (for the URLs): " URL_HOSTNAME
read -e -p "SMTP relay host (can be localhost): " SMTP_RELAY_HOST
read -e -p "E-mail address for certreq dialogue (empty=no dialogue): " DIALOGUE_EMAIL
read -e -p "E-mail address of the CA administrator: " CAADMIN_EMAIL

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

HOME=$HOME RANDFILE=`mktemp` ca-make.py --config=/etc/pyca/openssl.cnf

