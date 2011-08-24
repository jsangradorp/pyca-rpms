#!/usr/bin/python

########################################################################
# ca-revoke.py
# (c) by Michael Stroeder, michael@stroeder.com
########################################################################

__version__ = '0.6.6'

########################################################################
# This script is used to revoke certificates from the command line
# ca-revoke.py -h prints usage of parameters.
########################################################################

import sys, string, os, smtplib, getopt

from time import time,localtime,strftime,mktime

def findoption(options,paramname):
  for i in options:
    if i[0]==paramname:
      return i
  return ()

def PrintUsage(ErrorMsg='',ErrorCode=1):
  script_name = string.split(sys.argv[0],os.sep)[-1]
  sys.stderr.write("""*** %s *** (C) by Michael Stroeder, 1999

usage: %s [options]

Options:

  -h or --help
        Print out this message

  --config=[pathname]
	Pathname of OpenSSL configuration file.
        You may also use env variable OPENSSL_CONF.
	Default: /etc/openssl/openssl.cnf

  --pycalib=[directory]
        Specify directory containing the pyCA modules
        You may also use env variable PYCALIB.
	Default: /usr/local/pyca/pylib

  --name=[CA name]
        Name of CA in section [ca] of OpenSSL config.

  --serial=[hex number]
	Serial number of certificate to revoke.

""" % (script_name,script_name))
  if ErrorMsg:
    sys.stderr.write('Error: %s\n' % ErrorMsg)
  sys.exit(ErrorCode)

########################################################################
#                              Main
########################################################################

script_name=sys.argv[0]

try:
  options,args=getopt.getopt(sys.argv[1:],'h',['help','config=','pycalib=','name=','serial='])
except getopt.error,e:
  PrintUsage(str(e))

if findoption(options,'-h')!=() or findoption(options,'--help')!=():
  PrintUsage()

if findoption(options,'--config')!=():
  opensslcnfname = findoption(options,'--config')[1]
else:
  opensslcnfname = os.environ.get('OPENSSL_CONF','/etc/openssl/openssl.cnf')

if not os.path.isfile(opensslcnfname):
  PrintUsage('Config file %s not found.' % (opensslcnfname))

if findoption(options,'--pycalib')!=():
  pycalib = findoption(options,'--pycalib')[1]
else:
  pycalib = os.environ.get('PYCALIB','/usr/local/pyca/pylib')

if not os.path.exists(pycalib) or not os.path.isdir(pycalib):
  PrintUsage('Module directory %s not exists or not a directory.' % (pycalib))

sys.path.append(pycalib)

try:
  import openssl,charset
  from openssl.db import \
    empty_DN_dict, \
    DB_type,DB_exp_date,DB_rev_date,DB_serial,DB_file,DB_name,DB_number, \
    DB_TYPE_REV,DB_TYPE_EXP,DB_TYPE_VAL, \
    dbtime2tuple,GetEntriesbyDN,SplitDN
except ImportError:
  PrintUsage('Required pyCA modules not found in directory %s!' % (pycalib))

# Read the configuration file
if os.path.isfile('%s.pickle' % (opensslcnfname)):
  # Try to read OpenSSL's config file from a pickled copy
  f=open('%s.pickle' % (opensslcnfname),'rb')
  try:
    # first try to use the faster cPickle module
    from cPickle import load
  except ImportError:
    from pickle import load
  opensslcnf=load(f)
  f.close()
else:
  # Parse OpenSSL's config file from source
  opensslcnf=openssl.cnf.OpenSSLConfigClass(opensslcnfname)

pyca_section = opensslcnf.data.get('pyca',{})
ca_names = opensslcnf.sectionkeys.get('ca',[])

openssl.bin_filename = pyca_section.get('OpenSSLExec','/usr/local/ssl/bin/openssl')
if not os.path.isfile(openssl.bin_filename):
  sys.stderr.write('Did not find OpenSSL executable %s.\n' % (openssl.bin_filename))
  sys.exit(1)

if findoption(options,'--name')!=():
  ca_name = findoption(options,'--name')[1]
  if not ca_name in ca_names:
    PrintUsage('Wrong CA name.\nCA names listed in the current configuration:\n%s.' % string.join(ca_names,', '))
else:
  PrintUsage('You have to provide a name of a CA definition.')

if findoption(options,'--serial')!=():
  try:
    serial = string.atoi(findoption(options,'--serial')[1],16)
  except ValueError:
    PrintUsage('No valid serial number.')

else:
  PrintUsage('You have to provide the serial number of the certificate you want to revoke.')

ca = opensslcnf.getcadata(ca_name)

sys.stdout.write('Searching database %s for certificate %x...\n' % (ca.database,serial))
ca_db = openssl.db.OpenSSLcaDatabaseClass(ca.database)
result = ca_db.GetEntrybySerial(serial)

if result:
  sys.stdout.write("""Found the following certificate:
Serial number: %s
Distinguished Name: %s
""" % (result[DB_serial],charset.asn12iso(result[DB_name])))

  if result[DB_type]==DB_TYPE_REV:
    sys.stdout.write('Certificate already revoked since %s.\n' % strftime('%d.%m.%Y',localtime(mktime(dbtime2tuple(result[DB_rev_date])))))
    sys.exit(0)
  elif result[DB_type]==DB_TYPE_EXP:
    sys.stdout.write('Certificate already expired since %s.\n' % strftime('%d.%m.%Y',localtime(mktime(dbtime2tuple(result[DB_exp_date])))))
    sys.exit(0)
  elif result[DB_type]==DB_TYPE_VAL:
    sys.stdout.write('Valid until %s.\n\nRevoke the certificate? (y/n) ' % strftime('%d.%m.%Y',localtime(mktime(dbtime2tuple(result[DB_exp_date])))))
    answer = sys.stdin.readline()
    if string.lower(string.strip(answer))=='y':
      ca_db.Revoke(serial)
      sys.stdout.write('Certificate %x in %s marked as revoked.\n' % (serial,ca_name))
      # CA's private key present <=> we are on the private CA system
      if os.path.isfile(ca.certificate) and os.path.isfile(ca.private_key):
	sys.stdout.write('Issue new CRL? (y/n) ')
	answer = sys.stdin.readline()
	if string.lower(string.strip(answer))=='y':
	  sys.stdout.write('Issueing new CRL %s.\n' % (ca.crl))
	  rc = os.system('%s ca -config %s -name %s -gencrl -out %s' % \
                	 (openssl.bin_filename,opensslcnfname,ca.sectionname,ca.crl))
	  if rc:
            sys.stderr.write('Error %d creating CRL %s.\n' % (rc,ca.crl))

  else:
    raise ValueError, 'Unknown type field %s in certificate database.' % result[DB_type]

else:
  PrintUsage('No certificate found in "%s" with serial %x.\n' % (ca_name,serial))

