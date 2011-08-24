#!/usr/bin/python

"""
scep.py - Cisco System's Simple Certificate Enrollment Protocol
(c) by Michael Stroeder <michael@stroeder.com>

CGI-BIN for implementing SCEP
see: http://www.cisco.com/warp/public/cc/pd/sqsw/tech/scep_wp.htm
"""

Version='0.6.6'

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

import sys, os, re, string, \
       pycacnf, htmlbase, cgiforms, cgihelper, certhelper, openssl

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

form = cgiforms.formClass()
form.add(
  cgiforms.formSelectClass(
    'operation',
    'Operation',
    ['GetCACert','PKIOperation']
  )
)
form.add(
  cgiforms.formInputClass(
    'message',
    'Message',
    10000,
    (r'.*',re.M+re.S)
  )
)

form.getparams()

scep_operation = form.field['operation'][0].content
scep_message = form.field['message'][0].content

if scep_operation in ['GetCACert','GetCACertChain']:

  # *** Check parameter message again for being valid FQDN.

  # *** Set to pre-configured SCEP CA
  scep_message = 'SCEP'

  ca = opensslcnf.getcadata(scep_message)

  # Name der CA pruefen
  if not opensslcnf.data['ca'].has_key(scep_message):
    # CA-Definition nicht in openssl-Konfiguration enthalten
    htmlbase.PrintErrorMsg('Unknown certificate authority "%s".' % scep_message)
    sys.exit(0)

  # Does the certificate file exist?
  if not os.path.isfile(ca.certificate):
    htmlbase.PrintErrorMsg('CA Certificate of file not found.')
    sys.exit(0)

  cert = certhelper.pem2der(open(ca.certificate,'r').read())
  sys.stderr.write('%s' % repr(cert))
  # Simply write MIME-type and certificate data to stdout
  sys.stdout.write('Content-type: application/x-x509-ca-cert\n\n')
  sys.stdout.write(cert)
  sys.stdout.flush()

elif scep_operation=='PKIOperation':

  open('/tmp/scep_message','wb').write(scep_message)

sys.exit(0)
