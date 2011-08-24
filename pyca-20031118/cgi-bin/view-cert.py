#!/usr/bin/python

"""
view-cert.py
(c) by Michael Stroeder <michael@stroeder.com>

CGI-BIN for viewing certificates
with Netscape Navigator and M$ Internet Explorer

Input:

PATH_INFO
- Name of CA in openssl.cnf (section [ca] of openssl.cnf)
- Type of certificate ('email', 'user', 'ca', 'crl')
QUERY_STRING only for ('email', 'user')
- Serial number of desired certificate
  max. 8 digits hexadecimal (32 Bit)

Examples:
  view-cert.py/Persona/ca
  displays CA certificate of CA "Persona"

  view-cert.py/Persona/email?01
  displays client certificate of CA "Persona" with serial 0x01

  view-cert.py/Server/crl
  displays CRL of CA "Server"

  view-cert.py/Server/server?01
  displays server certificate of CA "Server" with serial 0x01
"""

__version__ = '0.6.6'

import sys,os,string,re,pycacnf,htmlbase,openssl,charset

from time import time,localtime,strftime,mktime

from pycacnf import opensslcnf, pyca_section

from openssl.db import \
  empty_DN_dict, \
  DB_type,DB_exp_date,DB_rev_date,DB_serial,DB_file,DB_name,DB_number, \
  DB_TYPE_REV,DB_TYPE_EXP,DB_TYPE_VAL, \
  dbtime2tuple,GetEntriesbyDN,SplitDN

# Wir lesen rein gar nix von Standardeingabe => gleich dicht machen
sys.stdin.close()

# Path to openssl executable
openssl.bin_filename = pyca_section.get('OpenSSLExec','/usr/bin/openssl')

# Ein paar Umgebungsvariablen auslesen, welche der Apache liefert
request_method  = os.environ.get('REQUEST_METHOD','')
query_string    = os.environ.get('QUERY_STRING','')
path_info       = os.environ.get('PATH_INFO','')[1:]

nsBaseUrl    = pyca_section.get('nsBaseUrl','/')
nsGetCertUrl = pyca_section.get('nsGetCertUrl','get-cert.py')
nsViewCertUrl = pyca_section.get('nsViewCertUrl','view-cert.py')

# Hier die ueblichen Paranoid-Pruefungen der Parameter

if request_method!='GET':
  # Skript nicht mit GET aufgerufen
  htmlbase.PrintErrorMsg('Wrong method.')
  sys.exit(0)

# Bezeichnung der Sub-CA und MIME-Typ aus PATH_INFO splitten
try:
  ca_name, cert_typeandformat = string.split(path_info,'/',1)
  cert_typeandformat=string.lower(cert_typeandformat)
except ValueError:
  htmlbase.PrintErrorMsg('Invalid parameter format.')
  sys.exit(0)

# Name der CA pruefen
if not opensslcnf.data['ca'].has_key(ca_name):
  # CA-Definition nicht in openssl-Konfiguration enthalten
  htmlbase.PrintErrorMsg('Unknown certificate authority "%s".' % ca_name)
  sys.exit(0)

if re.compile('^(ca|crl|server|user|email)(.(der|pem|b64|crt|crl))*$').match(cert_typeandformat) is None:
  htmlbase.PrintErrorMsg('Certificate type has invalid format.')
  sys.exit(0)

try:
  cert_type,cert_format = string.split(cert_typeandformat,'.',1)
except ValueError:
  cert_type,cert_format = cert_typeandformat,'der'
if cert_format=='crt' or cert_format=='crl':
  cert_format='der'

if len(query_string)>8:
  # Seriennummer mit mehr 32 Bit
  htmlbase.PrintErrorMsg('Serial number too long.')
  sys.exit(0)

if (not cert_type in ['ca','crl']) and (not query_string):
  # keine Seriennummer
  htmlbase.PrintErrorMsg('No serial number.')
  sys.exit(0)

# Process request

ca = opensslcnf.getcadata(ca_name)

if cert_type=='ca':
    # Abruf des CA-Zertifikates
    certfilename = ca.certificate
elif cert_type=='crl':
  certfilename = ca.crl
elif cert_type in ['user','email','server']:
  if re.compile('^[0-9a-fA-F]+$').match(query_string) is None:
    # Parameter war keine Hex-Nummer
    htmlbase.PrintErrorMsg('Serial number not in hexadecimal format.')
    sys.exit(0)
  # Abruf eines Zertifikates mittels Seriennummer
  serialnumber=string.atoi(query_string,16)
  entry = openssl.db.GetEntrybySerial(ca.database,serialnumber)
  # Kein entsprechender Eintrag gefunden
  if not entry:
    htmlbase.PrintErrorMsg('Certificate not found.')
    sys.exit(0)
  certfilename = os.path.join(ca.certs,'%s.pem' % (entry[DB_serial]))
else:
  # Zertifikattyp war nicht gueltig
  htmlbase.PrintErrorMsg('Invalid certificate type "%s"' % cert_type)
  sys.exit(0)

# Does the certificate file exist?
if not os.path.isfile(certfilename):
  htmlbase.PrintErrorMsg('Certificate file not found.')
  sys.exit(0)

if cert_type=='crl':

  htmlbase.PrintHeader('View CRL')
  htmlbase.PrintHeading('View CRL')
  crl = openssl.cert.CRLClass(certfilename)
  issuerdatalist = []
  for attr in openssl.cert.X509v1_certattrlist:
    issuerdatalist.append(string.strip(charset.asn12html4(crl.issuer.get(attr,''))))
  print """
<DL>
  <DT><STRONG>This CRL was issued by:</STRONG></DT>
  <DD>%s</DD>
  <DT><STRONG>last updated:</STRONG></DT>
  <DD>%s</DD>
  <DT><STRONG>next update:</STRONG></DT>
  <DD>%s</DD>
</DL>
<P><A HREF="%s%s/%s/crl.crl">Download CRL</A></P>
<HR><FONT SIZE=-1><PRE>
""" % ( \
        string.join(issuerdatalist,'<BR>'),
        crl.lastUpdate,crl.nextUpdate,
	nsBaseUrl,nsGetCertUrl,ca_name
      )
  sys.stdout.flush()
  os.system('%s crl -inform PEM -in "%s" -noout -text' %(openssl.bin_filename,ca.crl))
  sys.stdout.flush()
  print '</PRE></FONT>'
  htmlbase.PrintFooter()

elif cert_type=='ca':

  htmlbase.PrintHeader('View CA Certificate')
  htmlbase.PrintHeading('View CA Certificate')
  cert = openssl.cert.X509CertificateClass(certfilename)

  print """
%s
<P>
  <A HREF="%s%s/%s/ca.crt">Download certificate</A>
</P>
<HR><FONT SIZE=-1><PRE>
""" % (cert.htmlprint(),nsBaseUrl,nsGetCertUrl,ca_name)

  sys.stdout.flush()
  os.system('%s x509 -inform PEM -in "%s" -noout -text' %(openssl.bin_filename,certfilename))
  sys.stdout.flush()

  print '</PRE></FONT>'
  htmlbase.PrintFooter()

elif cert_type in ['user','email','server']:

  htmlbase.PrintHeader('View Certificate')
  htmlbase.PrintHeading('View Certificate')
  cert = openssl.cert.X509CertificateClass(certfilename)
  if entry[DB_type]==openssl.db.DB_TYPE_VAL:
    statusstr = 'Certificate is valid.'
  elif entry[DB_type]==openssl.db.DB_TYPE_REV:
    statusstr = 'Certificate revoked since %s.' % (strftime('%Y-%m-%d %H:%M',localtime(mktime(dbtime2tuple(entry[DB_rev_date])))))
  elif entry[DB_type]==openssl.db.DB_TYPE_EXP:
    statusstr = 'Certificate expired.'
  print """
<P>
  <DL>
    <DT><STRONG>Current status</STRONG>:</DT>
    <DD>%s</DD>
  </DL>
</P>
%s
</PRE></FONT>
""" % (statusstr,cert.htmlprint())
  print """
<P>
  <A HREF="%s%s/%s/%s.crt?%s">Download certificate</A> &nbsp;
  <A HREF="%s%s/%s/ca.crt">View issuer certificate</A>
</P>
<HR><FONT SIZE=-1><PRE>
""" % ( \
	nsBaseUrl,nsGetCertUrl,ca_name,cert_type,entry[DB_serial],
	nsBaseUrl,nsViewCertUrl,ca_name
      )
  sys.stdout.flush()
  os.system('%s x509 -inform PEM -in "%s" -noout -text' %(openssl.bin_filename,certfilename))
  sys.stdout.flush()
  print '</PRE></FONT>'
  htmlbase.PrintFooter()

sys.exit(0)

