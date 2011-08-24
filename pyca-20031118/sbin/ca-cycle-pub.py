#!/usr/bin/python

########################################################################
# ca-cycle-pub.py
# (c) by Michael Stroeder, michael@stroeder.com
########################################################################

__version__ = '0.6.6'

########################################################################
# This script is typically run by CRON or a similar task manager.
# It does several jobs (some not implemented yet):
# - Mark expired certificates in OpenSSL certificate database
# - Sort in new certificates and inform user via e-mail where to
#   download his certificate
# - Spool certificate requests and certificate revocation requests
# - Remove stale certificate requests from caPendCertReqDir
########################################################################

import sys, string, os, smtplib, getopt

from time import time,gmtime,localtime,strftime,mktime

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

""" % (script_name,script_name))
  if ErrorMsg:
    sys.stderr.write('Error: %s\n' % ErrorMsg)
  sys.exit(ErrorCode)

########################################################################
#                              Main
########################################################################

script_name=sys.argv[0]

try:
  options,args=getopt.getopt(sys.argv[1:],'h',['help','config=','pycalib='])
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

openssl.bin_filename = pyca_section.get('OpenSSLExec','/usr/local/ssl/bin/openssl')
if not os.path.isfile(openssl.bin_filename):
  PrintUsage('Did not find OpenSSL executable %s.' % (openssl.bin_filename))

MailRelay          = pyca_section.get('MailRelay','localhost')
nsGetCertUrl       = pyca_section.get('nsGetCertUrl','cgi-bin/get-cert.py')
nsViewCertUrl      = pyca_section.get('nsViewCertUrl','cgi-bin/view-cert.py')
caPendCertReqValid = 3600*string.atoi(pyca_section.get('caPendCertReqValid','0'))

newcert_mailtext = r"""From: %s
To: %s
Subject: Your certificate %d

The certificate you requested has been issued and is valid
from %s until %s.

You can retrieve your certificate from here:

  %s%s/%s/%s.crt?%x

Please use the same web browser on the same machine, with same
login and configuration data as when you created the certificate
request. Otherwise your software will likely refuse to install
the certificate.

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
! It is highly recommended to make a backup copy of your !
! private key and certificate right after installing it. !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

If you have further questions simply reply to this e-mail.

----------------------------------------------------------

%s

Detail view of your certificate:

  %s%s/%s/%s?%x
"""

gmt = time()
gmtstr = strftime('%Y%m%d%H%M%S',gmtime(gmt))

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
processed_new_reqs_dirs = []
processed_new_certs_dirs = []

for ca_name in ca_names:

  sys.stdout.write('\n\nProcessing certificate authority "%s"\n' % (ca_name))

  ca = opensslcnf.getcadata(ca_name)


  ######################################################################
  # Processing certificate database
  ######################################################################

  if not ca.database in processed_ca_databases:

    if os.path.isfile(ca.database):

      processed_ca_databases.append(ca.database)
      # Certificate database not processed up to now
      ca_db = openssl.db.OpenSSLcaDatabaseClass(ca.database)

      # Mark expired certificates in OpenSSL certificate database
      expired_db_entries = ca_db.Expire()
      if expired_db_entries:
        sys.stdout.write('The following entries were marked as expired:\n')
	for db_entry in expired_db_entries:
          sys.stdout.write('%s\n' % (charset.asn12iso(db_entry[DB_name])))

      # Mark expired certificates in OpenSSL certificate database
      expire_treshold=7*86400
      expired_db_entries = ca_db.ExpireWarning(expire_treshold)
      if expired_db_entries:
        sys.stdout.write('The following entries will expire soon:\n')
	for db_entry in expired_db_entries:
          sys.stdout.write('%s, %s, %s\n' % (
	      db_entry[DB_serial],
	      strftime('%Y-%m-%d %H:%M',localtime(mktime(dbtime2tuple(db_entry[DB_exp_date])))),
	      charset.asn12iso(db_entry[DB_name])
	    )
	  )

    else:
      sys.stderr.write('Warning: CA database file %s not found.\n' % (ca.database))


  ######################################################################
  # Move expired CRLs to archive
  ######################################################################

  if not ca.crl in processed_ca_crls:

    if os.path.isfile(ca.crl):

      processed_ca_crls.append(ca.crl)
      ca_crl = openssl.cert.CRLClass(ca.crl)

      if ca_crl.nextUpdate_secs<gmt:

        ca_archived_crl = os.path.join(ca.crl_dir,os.path.basename('%s-%s.pem' % (os.path.splitext(ca.crl)[0],gmtstr)))
        # Archive the copy in the preferred format
	os.rename(ca.crl,ca_archived_crl)
        sys.stdout.write('Archived expired CRL file %s.\n' % (ca_archived_crl))

    else:
      sys.stderr.write('Warning: CRL file %s not found.\n' % (ca.crl))


  ######################################################################
  # Remove stale certificate requests
  ######################################################################

  if caPendCertReqValid and \
     ca.pend_reqs_dir and \
     (not ca.pend_reqs_dir in processed_pend_reqs_dirs):

    processed_pend_reqs_dirs.append(ca.pend_reqs_dir)
    # pend_certs_dir not processed up to now
    if os.path.isdir(ca.pend_reqs_dir):

      pendcertfilenames = os.listdir(ca.pend_reqs_dir)
      stalecerts = 0
      for reqfilename in pendcertfilenames:
	reqpathname = os.path.join(ca.pend_reqs_dir,reqfilename)
	if gmt-caPendCertReqValid > os.path.getmtime(reqpathname):
          os.remove(reqpathname)
	  stalecerts = stalecerts+1

      if stalecerts:
	sys.stdout.write('Removed %d stale certificate requests from %s.\n' % (stalecerts,ca.pend_reqs_dir))

    else:
      pendcertfilenames = []
      sys.stderr.write('Directory %s not found!\n' % (ca.pend_reqs_dir))


  ######################################################################
  # New certificate requests
  ######################################################################

  if ca.new_reqs_dir and \
     (not ca.new_reqs_dir in processed_new_reqs_dirs):

    processed_new_reqs_dirs.append(ca.new_reqs_dir)
    # new_certs_dir not processed up to now
    if os.path.isdir(ca.new_reqs_dir):
      newreqfilenames = os.listdir(ca.new_reqs_dir)
      newreqcounter = 0
      for reqfilename in newreqfilenames:
        if os.path.splitext(reqfilename)[1] in ['.spkac','.pem']:
          newreqcounter = newreqcounter+1

      if newreqcounter:
        sys.stdout.write('%d valid certificate requests in %s.\n' % (newreqcounter,ca.new_reqs_dir))

    else:
      newcertfilenames = []
      sys.stderr.write('Directory %s not found!\n' % (ca.new_reqs_dir))


  ######################################################################
  # Publish new client certificates and inform user via e-mail where to
  # download his certificate
  ######################################################################

  if (not ca.new_certs_dir in processed_new_certs_dirs) and \
     os.path.isfile(ca.certificate):

    processed_new_certs_dirs.append(ca.new_certs_dir)

    # new_certs_dir not processed up to now
    newcertfilenames = os.listdir(ca.new_certs_dir)

    if newcertfilenames:
      sys.stdout.write('Publish %d new certificates in %s.\n' % (len(newcertfilenames),ca.new_certs_dir))
      if ca.isservercert():
        certtype = 'server'
      elif ca.isclientcert():
        certtype = 'user'
      else:
        certtype = 'user'

    for certfilename in newcertfilenames:

      newcertpathname = os.path.join(ca.new_certs_dir,certfilename)
      cert = openssl.cert.X509CertificateClass(newcertpathname)

      if openssl.db.GetEntrybySerial(ca.database,cert.serial):

	certpathname = os.path.join(ca.certs,certfilename)

        if not os.path.isfile(certpathname):

          import mimify

          issuername = charset.asn12iso(cert.issuer.get('CN',''))
	  issueremail = cert.issuer.get('Email','root@localhost')
          subjectname = charset.asn12iso(cert.subject.get('CN',''))
	  subjectemail = cert.subject.get('Email','')
          from_addr = mimify.mime_encode_header('%s <%s>' % (issuername,issueremail))
	  if subjectemail:
	    to_name,to_email = subjectname,subjectemail
          else:
	    to_name,to_email = issuername,issueremail
          to_addr = mimify.mime_encode_header('%s <%s>' % (to_name,to_email))

	  # Mailbody
	  mail_msg = newcert_mailtext % (
	               from_addr,
		       to_addr,
		       cert.serial,
		       strftime('%Y-%m-%d %H:%M',gmtime(cert.notBefore_secs)),
		       strftime('%Y-%m-%d %H:%M',gmtime(cert.notAfter_secs)),
		       ca.nsBaseUrl,nsGetCertUrl,ca_name,certtype,cert.serial,
		       cert.asciiprint(),
		       ca.nsBaseUrl,nsViewCertUrl,ca_name,certtype,cert.serial,
		     )

	  smtpconn=smtplib.SMTP(MailRelay)
	  smtpconn.set_debuglevel(0)
	  try:
	    smtpconn.sendmail(issueremail,to_email,mail_msg)
	    sys.stderr.write('Sent e-mail to %s <%s>.\n' % (to_name,to_email))
	  except:
	    sys.stderr.write('Unable to send an e-mail to %s <%s>.\n' % (to_name,to_email))
	  smtpconn.quit()

          # Move file from newcerts to certs dir
   	  os.rename(newcertpathname,certpathname)

	else:
          sys.stderr.write('Target file %s already exists. Maybe something went wrong?\n' % (certfilename))

      else:
        sys.stderr.write('Did not find certificate with serial number %d in file %s! Certificate database up to date?\n' % (cert.serial,ca.database))


######################################################################
# Spool certificate requests and certificate revocation requests
# to system holding the private keys
######################################################################

pass


######################################################################
# Check again if everything is in place and give out summary report
######################################################################

sys.stdout.write('\n\n##### Summary report #####\n\n')

for ca_name in ca_names:

  ca = opensslcnf.getcadata(ca_name)

  sys.stdout.write('CA definition "%s":\n' % (ca_name))
  if not os.path.isfile(ca.crl):
    sys.stderr.write('Warning: No valid CRL file %s after processing.\n' % (ca.crl))
  else:
    ca_crl = openssl.cert.CRLClass(ca.crl)
    sys.stdout.write('CRL file %s valid from %s until %s.\n' % (ca.crl,ca_crl.lastUpdate,ca_crl.nextUpdate))

