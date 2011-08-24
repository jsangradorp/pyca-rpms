#!/usr/bin/python

"""
ca-certreq-mail.py
(c) by Michael Stroeder, michael@stroeder.com

This script is intended to handle the confirmation mail for a
cert request.
It receives the mail on stdin and moves the certificate request file
from pend_reqs_dir to new_reqs_dir. If the senders from:
address is different of the one in the certificate request the sender
is notified about this by e-mail.
If an error occurs the exit code is still zero to prevent the
mail system from generating a bounce revealing internal informations.
"""

__version__ = '0.6.6'

import sys, os, shutil, time, string, smtplib, rfc822, getopt
from mimify import mime_decode_header, mime_encode_header

# Einen Datensatz in Protokolldatei schreiben
# log		Filehandle von bereits geoeffneter Protokolldatei
# Kategorie	des Eintrags, z.B. 'Error:'
# Mail		Mailheader
# Kommentar	klar
def LogWrite(log,Kategorie,Mail,Kommentar):
  log.write('%s %s: ' % (time.strftime('%d.%m.%Y %X',time.localtime(time.time())),Kategorie))
  if Mail:
    for i in ['from','subject','message-id']:
      if Mail.has_key(i):
	log.write('%s ' % (Mail[i]))
  log.write('%s\n' % (Kommentar))
  return

def findoption(options,paramname):
  for i in options:
    if i[0]==paramname:
      return i
  return ()


########################################################################
#                              Main
########################################################################

script_name=sys.argv[0]


# The log file can only be stderr as long as the config is not read
logfile = sys.stderr

# Parse command-line options
try:
  options,args=getopt.getopt(sys.argv[1:],'h',['help','config=','pycalib='])
except getopt.error,e:
  LogWrite(logfile,'Error',None,str(e))

# Try to find modules directory
if findoption(options,'--pycalib')!=():
  pycalib = findoption(options,'--pycalib')[1]
else:
  pycalib = os.environ.get('PYCALIB','/usr/local/pyca/pylib')
if not os.path.exists(pycalib) or not os.path.isdir(pycalib):
  LogWrite(logfile,'Error',None,'Module directory %s not exists or not a directory.' % (pycalib))
sys.path.append(pycalib)

if findoption(options,'--config')!=():
  opensslcnfname = findoption(options,'--config')[1]
else:
  opensslcnfname = os.environ.get('OPENSSL_CONF','/etc/openssl/openssl.cnf')

if not os.path.isfile(opensslcnfname):
  LogWrite(logfile,'Error',None,'Config file %s not found.' % (opensslcnfname))

import openssl,charset
from openssl.db import \
  empty_DN_dict, \
  DB_type,DB_exp_date,DB_rev_date,DB_serial,DB_file,DB_name,DB_number, \
  DB_TYPE_REV,DB_TYPE_EXP,DB_TYPE_VAL, \
  dbtime2tuple,GetEntriesbyDN,SplitDN

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

logfile_name = pyca_section.get('caCertConfirmReqLog','/var/log/pyca/ca-certreq-mail.out')
logfile = open(logfile_name,'a')

openssl.bin_filename = pyca_section.get('OpenSSLExec','/usr/local/ssl/bin/openssl')
if not os.path.isfile(openssl.bin_filename):
  LogWrite(logfile,'Error',None,'Did not find OpenSSL executable %s.' % (openssl.bin_filename))

ca_names = opensslcnf.sectionkeys.get('ca',[])
MailRelay           = pyca_section.get('MailRelay','localhost')
caCertReqMailAdr    = pyca_section.get('caCertReqMailAdr','')
caInternalCertTypes = pyca_section.get('caInternalCertTypes',[])
caInternalDomains   = pyca_section.get('caInternalDomains','')
if type(caInternalDomains)!=type([]):
  caInternalDomains = [caInternalDomains]

#############################################################
# Hauptprogramm
#############################################################

m=rfc822.Message(sys.stdin)

#############################################################
# Format von Subject und Body ueberpruefen
# Wirkt recht paranoid, soll aber gegen Muellmails schuetzen
#############################################################

# Ueberlange Subjects verbieten
if len(m["subject"])>80:
  LogWrite(logfile,'Error',m,'Subject too long.')
  sys.exit(0)

if m.has_key('from'):
  from_addr = mime_decode_header(string.strip(m["from"]))
  from_name, from_mail = rfc822.AddressList(from_addr).addresslist[0]
else:
  from_mail = ''

subject = string.strip(m["subject"])
subjectstart = string.find(subject,'cert-req-')

# Format dreiteilig?
try:
  prefix,ca_name,caChallengeId = string.split(subject[subjectstart:len(subject)],'.',2)
except ValueError:
  LogWrite(logfile,'Error',m,'Subject has wrong format.')
  sys.exit(0)

# Prefix richtig?
if prefix=='cert-req-SPKAC':
  request_filenamesuffix = 'spkac'
elif prefix=='cert-req-PKCS10':
  request_filenamesuffix = 'pem'
else:
  LogWrite(logfile,'Error',m,'Subject has wrong format.')
  sys.exit(0)

# ChallengeID nicht zu lang?
if len(caChallengeId)>30:
  LogWrite(logfile,'Error',m,'caChallengeId %s has bad format.' % (caChallengeId))
  sys.exit(0)

# CA Name gueltig?
if not (ca_name in ca_names):
  LogWrite(logfile,'Error',m,'ca_name "%s" wrong.' % (ca_name))
  sys.exit(0)

ca = opensslcnf.getcadata(ca_name)

# Eine Benutzerantwort ist eingetroffen
request_filename = os.path.join(ca.pend_reqs_dir,'%s.%s.%s' % (prefix,ca_name,caChallengeId))

pubkey_filename = '%s.%s' % (request_filename,request_filenamesuffix)

# Existieren die benoetigten Dateien?
if not os.path.isfile(pubkey_filename):
  LogWrite(logfile,'Error',m,'Certificate request file %s not found.' % (pubkey_filename))
  sys.exit(0)

# Hier sind jetzt alle Angaben gueltig, soweit pruefbar

newrequest_filename = os.path.join(ca.new_reqs_dir,'%s.%s.%s' % (prefix,ca_name,caChallengeId))
target_pubkey_filename = '%s.%s' % (newrequest_filename,request_filenamesuffix)

# Now copy files to target directory, use copy to get new ownership
try:
  shutil.copyfile(pubkey_filename,target_pubkey_filename)
  os.chmod(target_pubkey_filename,0440)
except IOError:
  LogWrite(logfile,'Error',m,'Copying %s to %s failed.' % (pubkey_filename,target_pubkey_filename))
  sys.exit(0)
else:
  try:
    os.remove(pubkey_filename)
  except IOError:
    LogWrite(logfile,'Error',m,'Removing %s failed.' % (pubkey_filename))
    sys.exit(0)

LogWrite(logfile,'Challenge',m,'Request challenge: %s Id=%s' % (ca_name,caChallengeId))

# FIX ME! We also would like to look into PKCS10 requests!
if prefix!='cert-req-SPKAC':
  sys.exit(0)

# Read the certificate request file
certreq = openssl.cert.SPKACClass(target_pubkey_filename)

certreq_name_attr = certreq.data.get('commonName','')
certreq_mail_attr = certreq.data.get('emailAddress','')

if (certreq_name_attr and from_name!=certreq_name_attr) or \
   (certreq_mail_attr and from_mail!=certreq_mail_attr):

  cacert = openssl.cert.X509CertificateClass(ca.certificate)
  ca_from_addr = cacert.subject.get('Email',pyca_section.get('caAdminMailAdr',''))
  mail_msg = """From: %s <%s>
To: %s
Subject: Your confirmation e-mail with ID %s

We received the correct confirmation e-mail for your
certificate request.

However the from: field of your confirmation e-mail

  From: %s

did not match the attributes

  commonName   = %s
  emailAddress = %s

given in your certificate request. Your certificate request will
be processed anyway. But if you intend to use the requested
certificate for signing e-mails you might want to adjust the from
address in your mail clients preferences / options menu to avoid
trouble with other mail users reporting invalid signatures.

If you have further questions simply reply to this e-mail.
""" % (
  mime_encode_header(
    charset.t612iso(
      cacert.subject.get('CN','CA administrator'))
    ),
    ca_from_addr,
  certreq_mail_attr,
  caChallengeId,
  from_addr,
  certreq_name_attr,certreq_mail_attr
)

  try:
    smtpconn=smtplib.SMTP(MailRelay)
    try:
      try:
        smtpconn.set_debuglevel(0)
        smtpconn.sendmail(ca_from_addr,certreq_mail_attr,mail_msg)
      finally:
        smtpconn.quit()
    except:
      LogWrite(logfile,'Error',m,'Unable to send an e-mail to %s!\n' % (certreq_mail_attr))
    else:
      LogWrite(logfile,'Error',m,'Sent from address warning to %s!\n' % (certreq_mail_attr))
  except socket.error:
    LogWrite(logfile,'Error',m,'Unable to contact default mail relay %s!\n' % (MailRelay))

sys.exit(0)
