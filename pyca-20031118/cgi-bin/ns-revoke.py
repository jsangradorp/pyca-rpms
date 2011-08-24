#!/usr/bin/python

"""
ns-revoke.py
(c) by Michael Stroeder <michael@stroeder.com>

CGI-BIN for revoking client certificates
Input:

PATH_INFO
- Name of CA in openssl.cnf (section [ca] of openssl.cnf)
QUERY_STRING
- Serial number of certificate to revoke
  max. 8 digits hexadecimal (32 Bit)

Example:
  ns-revoke.py/Persona?01
  revokes client certificate with serial 0x01 of CA "Persona"

The following checks are made to avoid denial of service attacks:
- The client software must provide the client certificate.
- The issuer of the client and the server certificates must match
"""

Version='0.6.6'

import sys, os, string, re, pycacnf, htmlbase, openssl, cgissl, certhelper

from pycacnf import opensslcnf, pyca_section

# Wir lesen rein gar nix von Standardeingabe => gleich dicht machen
sys.stdin.close()

# Path to openssl executable
openssl.bin_filename = pyca_section.get('OpenSSLExec','/usr/bin/openssl')

# Ein paar Umgebungsvariablen auslesen, welche der Apache liefert
request_method  = os.environ.get('REQUEST_METHOD','')
query_string    = os.environ.get('QUERY_STRING','')
script_name    = os.environ.get('SCRIPT_NAME','')
path_info       = os.environ.get('PATH_INFO','')[1:]

rm = (re.compile('[0-9a-fA-F]+(&yes)*')).match(query_string)

# Hier die ueblichen Paranoid-Pruefungen der Parameter
if request_method!='GET':
  # Skript nicht mit GET aufgerufen
  htmlbase.PrintErrorMsg('Wrong method.')
  sys.exit(0)

# Angabe der CA pruefen
ca_name = os.environ.get('PATH_INFO','')[1:]

if not ca_name:
  htmlbase.PrintErrorMsg('No certificate authority.')
  sys.exit(0)

# Name der CA pruefen
if not opensslcnf.data['ca'].has_key(ca_name):
  # CA-Definition nicht in openssl-Konfiguration enthalten
  htmlbase.PrintErrorMsg('Unknown certificate authority "%s".' % ca_name)
  sys.exit(0)

ca = opensslcnf.getcadata(ca_name)

# Abruf eines Zertifikates mittels Seriennummer
try:
  serial,yes = string.split(query_string,'_')
except ValueError:
  serial = query_string

serialnumber=string.atoi(serial,16)

ca_db = openssl.db.OpenSSLcaDatabaseClass(ca.database)
entry = ca_db.GetEntrybySerial(serialnumber)

# Kein entsprechender Eintrag gefunden
if not entry:
  htmlbase.PrintErrorMsg('Certificate not found.')
  sys.exit(0)

# Zertifikat ist ungueltig
if entry[openssl.db.DB_type]!=openssl.db.DB_TYPE_VAL:
  htmlbase.PrintErrorMsg('Certificate invalid.')
  sys.exit(0)

certfilename = os.path.join(ca.certs,'%s.pem' % (entry[openssl.db.DB_serial]))

# Does the certificate file exist?
if not os.path.isfile(certfilename):
  htmlbase.PrintErrorMsg('Certificate file not found.')
  sys.exit(0)

# Kein Zertifikat mit angegebener Nummer gefunden
if entry==[]:
  htmlbase.PrintErrorMsg('Certificate not found.')
  sys.exit(0)

if entry[openssl.db.DB_type]!=openssl.db.DB_TYPE_VAL:
  htmlbase.PrintErrorMsg('Certificate invalid.')
  sys.exit(0)

ssl_env = cgissl.GetAllSSLEnviron()

if not ssl_env.has_key('SSL_CLIENT_S_DN'):
  htmlbase.PrintErrorMsg('No client certificate present.')
  sys.exit(0)

cacert = openssl.cert.X509CertificateClass(ca.certificate)

#if ssl_env['SSL_CLIENT_I_DN']!=ssl_env['SSL_SERVER_I_DN']:
#  htmlbase.PrintErrorMsg('Wrong issuer of client certificate.')
#  sys.exit(0)

if ssl_env['SSL_CLIENT_S_DN']!=entry[openssl.db.DB_name]:
  htmlbase.PrintErrorMsg('Wrong client certificate.')
  sys.exit(0)

cert = openssl.cert.X509CertificateClass(certfilename)

if query_string[-4:]!='_yes':
  htmlbase.PrintHeader('Confirmation of certificate revocation.')
  print """The following certificate will be revoked:
%s
Are you really sure that you want to revoke your certificate?
The following reasons can make revoking necessary:
<UL>
  <LI>Your private key was compromised (stolen, the password was sniffed etc.)</LI>
  <LI>The content of the certificate attributes has become wrong.</LI>
</UL>
<A HREF="%s/%s?%s_yes">YES</A>
"""  % (cert.htmlprint(),script_name,ca_name,serialnumber)
  htmlbase.PrintFooter()
  sys.exit(0)

ca_db.Revoke(serialnumber)
htmlbase.PrintHeader('Revoked certificate.')
print 'The following certificate was revoked by you: %s' % (cert.htmlprint())
  
sys.exit(0)

