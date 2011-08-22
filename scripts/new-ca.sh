#!/bin/bash
read -e -p "ISO country code [XX]: " COUNTRY_CODE
read -e -p "State/Province Name []: " STATE_OR_PROVINCE
read -e -p "Location []: " LOCATION
read -e -p "Organization [Looser Org.]: " ORGANIZATION
read -e -p "Organizational Unit Name [bad CA!]: " ORGANIZATIONAL_UNIT
read -e -p "hostname (for the URLs): " URL_HOSTNAME


sed -i -e "s#\\(countryName_default[ \\t]*=[ \\t]*\\).*#\\1$COUNTRY_CODE#g" /etc/pyca/*
sed -i -e "s#\\(stateOrProvinceName_default[ \\t]*=[ \\t]*\\).*#\\1$STATE_OR_PROVINCE#g" /etc/pyca/*
sed -i -e "s#\\(localityName_default[ \\t]*=[ \\t]*\\).*#\\1$LOCATION#g" /etc/pyca/*
sed -i -e "s#\\(organizationName_default[ \\t]*=[ \\t]*\\).*#\\1$ORGANIZATION#g" /etc/pyca/*
sed -i -e "s#\\(organizationalUnitName_default[ \\t]*=[ \\t]*\\).*#\\1$ORGANIZATIONAL_UNIT#g" /etc/pyca/*
sed -i -e "s#\\(commonName_default[ \\t]*=[ \\t]*\\)\"\\(.*\\)[ \\t]\\+TestCA\"#\\1\"$ORGANIZATION \\2 CA\"#g" /etc/pyca/*
#sed -i -e "s#\\([^ ]\\+\\) \\+TestCA\\>#$ORGANIZATION \\1 CA#g" /etc/pyca/*
sed -i -e "s#localhost#$URL_HOSTNAME#g" /etc/pyca/*

RANDFILE=`mktemp` ca-make.py --config=/etc/pyca/openssl.cnf

