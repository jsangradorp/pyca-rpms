#!/usr/bin/python

"""
get-cert.py
(c) by Michael Stroeder <michael@stroeder.com>

CGI-BIN for downloading and installing certificates
with Netscape Navigator and M$ Internet Explorer

Input:

PATH_INFO
- Name of CA in openssl.cnf (section [ca] of openssl.cnf)
- Type of certificate ('email', 'user', 'ca', 'crl')
QUERY_STRING only for ('email', 'user')
- Serial number of desired certificate
  max. 8 digits hexadecimal (32 Bit)

Examples:
  get-cert.py/Persona/ca
  sends CA certificate of CA "Persona"

  get-cert.py/Persona/email?01
  sends client certificate of CA "Persona" with serial 0x01

  get-cert.py/Server/crl
  sends CRL of CA "Server"

  get-cert.py/Server/server?01
  sends PEM-encoded server certificate of CA "Server" with serial 0x01
"""

__version__='0.6.6'

def ReadCertFromFileObject(f):
  # Zertifikat aus Dateiobject certfile lesen
  cert = f.read()
  rc = f.close()
  return cert

def ReadCertsFromFileNames(pathnames):
  result = []
  for pathname in pathnames:
    f = open(pathname,'r')
    result.append(ReadCertFromFileObject(f))
  return string.join(result,'')

import sys,os,string,re,pycacnf,htmlbase,cgihelper,certhelper,openssl

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
OpenSSLExec = pyca_section.get('OpenSSLExec','/usr/bin/openssl')

# Ein paar Umgebungsvariablen auslesen, welche der Apache liefert
request_method  = os.environ.get('REQUEST_METHOD','')
query_string    = os.environ.get('QUERY_STRING','')
path_info       = os.environ.get('PATH_INFO','')[1:]
browser_name,browser_version = cgihelper.BrowserType(os.environ.get('HTTP_USER_AGENT',''))

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
  # Does the certificate file exist?
  if not os.path.isfile(ca.certificate):
    htmlbase.PrintErrorMsg('CA certificate file not found.')
    sys.exit(0)
  cert = open(ca.certificate,'r').read()
  if browser_name=='MSIE':
    mimetype = 'application/pkix-cert'
  else:
    mimetype = 'application/x-x509-ca-cert'

elif cert_type=='crl':

  # Does the certificate file exist?
  if not os.path.isfile(ca.crl):
    htmlbase.PrintErrorMsg('CRL file not found.')
    sys.exit(0)
  cert = open(ca.crl,'r').read()
  if browser_name=='MSIE':
    mimetype = 'application/pkix-crl'
  else:
    mimetype = 'application/x-pkcs7-crl'

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

  # Zertifikat ist ungueltig
  if entry[DB_type]!=openssl.db.DB_TYPE_VAL:
    htmlbase.PrintErrorMsg('Certificate invalid.')
    sys.exit(0)

  certfilename = os.path.join(ca.certs,'%s.pem' % (entry[DB_serial]))

  # Does the certificate file exist?
  if not os.path.isfile(certfilename):
    htmlbase.PrintErrorMsg('Certificate file not found.')
    sys.exit(0)

  # get list of CA names for which intermediate CA certs should be included
  caIntermediateCACerts = pyca_section.get('caIntermediateCACerts',[])
  if type(caIntermediateCACerts)==type(''):
    # Work around a deficiency in config parser
    caIntermediateCACerts = [caIntermediateCACerts]
  if ca_name in caIntermediateCACerts:
    ca_certfilenames = opensslcnf.getcacertchain(ca_name)
    for ca_certfilename in ca_certfilenames:
      if not os.path.isfile(ca_certfilename):
	htmlbase.PrintErrorMsg('Certificate file of intermediate CA not found.')
	sys.exit(0)
  else:
    ca_certfilenames = []

  if cert_type=='server':
    # Server certificates are downloaded or displayed in browser
    cert = open(certfilename,'r').read()
    if cert_format=='der':
      mimetype = 'application/octet-stream'
    else:
      mimetype = 'text/plain'

  elif cert_type=='email':
    cert = open(certfilename,'r').read()
    if browser_name=='MSIE':
      mimetype = 'application/pkix-cert'
    else:
      mimetype = 'application/x-x509-email-cert'

  elif cert_type=='user':
    if browser_name=='MSIE':
      command = '%s crl2pkcs7 -nocrl -certfile %s' % (OpenSSLExec,certfilename)
      for ca_certfilename in ca_certfilenames:
	command = command + ' -certfile %s ' % (ca_certfilename)
      cert = ReadCertFromFileObject(os.popen(command))
    else:
      cert = open(certfilename,'r').read()
      mimetype = 'application/x-x509-user-cert'

else:
  # Zertifikattyp war nicht gueltig
  htmlbase.PrintErrorMsg('Invalid certificate type "%s"' % cert_type)
  sys.exit(0)

if browser_name=='MSIE' and cert_type=='user':
  import vbs, charset
  htmlbase.PrintHeader('Install certificate')
  htmlbase.PrintHeading('Install certificate')
  print 'Certificate of type <STRONG>%s</STRONG>:<P>' % ca_name
  print 'Subject DN: %s<BR>Valid until: %s' % ( \
    charset.asn12html4(entry[DB_name]), \
    strftime('%d.%m.%Y',localtime(mktime(dbtime2tuple(entry[DB_exp_date])))) \
  )
  vbs.PrintVBSXenrollObject()
  print '<SCRIPT Language=VBSCRIPT>\n<!-- '
  vbs.PrintVBSCertInstallCode(string.strip(entry[DB_name]),entry[DB_serial],strftime('%d.%m.%Y',localtime(mktime(dbtime2tuple(entry[DB_exp_date])))),cert)
  print ' -->\n</SCRIPT>'
  htmlbase.PrintFooter()
else:
  # Simply write MIME-type and certificate data to stdout
  sys.stdout.flush()
  sys.stdout.write('Content-type: %s\n\n' % mimetype)
  if cert_format=='der':
    sys.stdout.write(certhelper.pem2der(cert))
  elif cert_format=='pem':
    pem_type = {0:'CERTIFICATE',1:'CRL'}[cert_type=='crl']
    sys.stdout.write("""-----BEGIN %s-----
%s
-----END %s-----
""" % (pem_type,certhelper.extract_pem(cert)[0][1],pem_type))
  elif cert_format=='b64':
    sys.stdout.write(certhelper.extract_pem(cert)[0][1])

sys.exit(0)
