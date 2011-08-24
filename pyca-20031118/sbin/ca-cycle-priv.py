#!/usr/bin/python

########################################################################
# ca-cycle-priv.py
# (c) by Michael Stroeder, michael@stroeder.com
########################################################################

__version__ = '0.6.6'

########################################################################
# Process some modifications which involve private CA keys.
# This script is typically run by CRON or in a similar manner.
# It does several jobs:
# - Mark expired certificates in OpenSSL certificate database 
# - Process certificate requests
# - Process certificate revocation requests
# - Generate new CRLs, move old CRLs to archive
# Special notes:
# The private systems only handles PEM format certificate data
########################################################################

import sys, string, os, stat, time, getopt

def filenotvalid(pathname):
  return not os.path.isfile(pathname) or os.stat(pathname)[stat.ST_SIZE]==0

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
	Default: /usr/local/pyca/pylib

  --issuecrls
        Force issuing of new CRLs
	Default: CRLs are only created if no valid CRL is present

""" % (script_name,script_name))
  if ErrorMsg:
    sys.stderr.write('Error: %s\n' % ErrorMsg)
  sys.exit(ErrorCode)

########################################################################
#                              Main
########################################################################

script_name=sys.argv[0]

try:
  options,args=getopt.getopt(sys.argv[1:],'h',['help','config=','pycalib=','issuecrls'])
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

issuecrls = findoption(options,'--issuecrls')!=()

if not os.path.exists(pycalib) or not os.path.isdir(pycalib):
  PrintUsage('Module directory %s not exists or not a directory.' % (pycalib))

sys.path.append(pycalib)

try:
  import openssl
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

openssl.bin_filename = pyca_section.get('OpenSSLExec','/usr/local/ssl/bin/openssl')
if not os.path.isfile(openssl.bin_filename):
  PrintUsage('Did not find OpenSSL executable %s.' % (openssl.bin_filename))

ca_names = opensslcnf.sectionkeys.get('ca',[])

gmt = time.time()
gmtstr = time.strftime('%Y%m%d%H%M%S',time.gmtime(gmt))

######################################################################
# Spool certificates and certificate revocation lists
# from system holding the private keys
######################################################################

pass

######################################################################
# CA specific actions
######################################################################

ca_names = opensslcnf.sectionkeys.get('ca',[])

# Lists of processed files and dirs to avoid double-processing
processed_ca_databases = []
processed_ca_crls = []
processed_pend_reqs_dirs = []
processed_new_certs_dirs = []

for ca_name in ca_names:

  sys.stdout.write("""
#############################################################
# Processing CA "%s"
#############################################################\n\n
""" % (ca_name))

  ca = opensslcnf.getcadata(ca_name)

  ########################################################################
  # Processing certificate database
  ########################################################################

  if not ca.database in processed_ca_databases:

    if os.path.isfile(ca.database):

      processed_ca_databases.append(ca.database)
      # Certificate database not processed up to now
      ca_db = openssl.db.OpenSSLcaDatabaseClass(ca.database)
      # Mark expired certificates in OpenSSL certificate database
      ca_db.Expire()
      
    else:
      sys.stderr.write('Warning: CA database file %s not found.\n' % (ca.database))


  ########################################################################
  # Process certificate requests
  ########################################################################

  pass

  ########################################################################
  # Process certificate revocation requests
  ########################################################################

  pass

  ########################################################################
  # Generate new CRLs, move old CRLs to archive
  ########################################################################

  sys.stdout.write("""
#############################################################
# Move expired CRLs to archive and generate new CRLs
#############################################################\n
Use password of each CA here.\n
""")

  if not ca.crl in processed_ca_crls:

    if os.path.isfile(ca.crl):

      processed_ca_crls.append(ca.crl)
      ca_crl = openssl.cert.CRLClass(ca.crl)
      
      if issuecrls or (ca_crl.nextUpdate_secs<=gmt+ca.crl_treshold*3600):

        # CRL is expired => move it to archive
        ca_archived_crl = os.path.join(ca.crl_dir,os.path.basename('%s-%s.pem' % (os.path.splitext(ca.crl)[0],gmtstr)))
        os.rename(ca.crl,ca_archived_crl)
        sys.stdout.write('Archived expired CRL file %s.\n' % (ca.crl))

    if filenotvalid(ca.crl):
      if os.path.isfile(ca.certificate) and os.path.isfile(ca.private_key):
	if os.path.isfile(ca.database):

	  sys.stdout.write('Issuing new CRL %s.\n' % (ca.crl))
	  rc = os.system('%s ca -config %s -name %s -gencrl -out %s' % \
                	 (openssl.bin_filename,opensslcnfname,ca.sectionname,ca.crl))
	  if rc:
            sys.stderr.write('Error %d creating CRL %s.\n' % (rc,ca.crl))

	else:
	  sys.stderr.write('Warning: CA database file %s not found.\n' % (ca.database))
      else:
	sys.stderr.write('CA cert %s or CA key %s missing.\n' % (ca.certificate,ca.private_key))

    if filenotvalid(ca.crl):
      sys.stderr.write('Warning: No valid CRL file %s after processing.\n' % (ca.crl))

