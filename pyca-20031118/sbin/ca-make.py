#!/usr/bin/python

"""
ca-make.py - boot-strap of certificate authorities
(c) by Michael Stroeder, michael@stroeder.com

This script creates if non-existent (in the order given below,
does not overwrite existing files with file length > 0):

Directory structure:
dir		Where everything is kept
certs		Where the issued certs are kept
new_certs_dir	default place for new certs.
crl_dir		Where the issued crl are kept

Files:
database	database index file.
serial		The current serial number

Certificate files:
private_key	The private key of the CA
certificate	The CA certificate
"""

__version__ = '0.6.6'

import sys, string, os, stat, pwd, grp, getopt, time

def filenotvalid(pathname):
  return not os.path.isfile(pathname) or os.stat(pathname)[stat.ST_SIZE]==0

def CheckedMakeDir(dirname,perms=0,uid=0,gid=0):

  if not dirname:
    return

  if os.path.exists(dirname):
    # Directory does already exist
    if not os.path.isdir(dirname):
      sys.stderr.write('Warning: %s already exists but is no directory.\n' % (dirname))
  else:
    # Create directory 
    try:
      os.makedirs(dirname)
      sys.stdout.write('Created directory %s\n' % (dirname))
    except OSError:
      sys.stderr.write('Error: Could not create directory %s.\n' % (dirname))
      return

  # Get current file stat info
  fstat = os.stat(dirname)

  if perms:
    os.chmod(dirname,perms)
    sys.stdout.write('Changed permissions of %s to %o\n' % (dirname,perms))

  if (uid and fstat[stat.ST_UID]!=uid) or \
     (gid and fstat[stat.ST_GID]!=gid):
    if not uid:
      uid=fstat[stat.ST_UID]
    if not gid:
      gid=pwd.getpwuid(uid)[3]
    os.chown(dirname,uid,gid)
    sys.stdout.write('Changed owner/group of %s to %s.%s\n' % (dirname,pwd.getpwuid(uid)[0],grp.getgrgid(gid)[0]))

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
  import openssl, charset
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

OpenSSLExec = openssl.bin_filename

currentusername = pwd.getpwuid(os.getuid())[0]

# Getting UIDs
# Set current UID as default
uidCAAdmin    = pwd.getpwnam(pyca_section.get('userCAAdmin',currentusername))[2]
uidMailDaemon = pwd.getpwnam(pyca_section.get('userMailDaemon',currentusername))[2]
uidWWWRun     = pwd.getpwnam(pyca_section.get('userWWWRun',currentusername))[2]
gidCAAdmin    = pwd.getpwuid(uidCAAdmin)[3]
gidMailDaemon = pwd.getpwuid(uidMailDaemon)[3]
gidWWWRun     = pwd.getpwuid(uidWWWRun)[3]

ca_names = opensslcnf.sectionkeys.get('ca',[])


sys.stdout.write("""
#############################################################
# Create directories and various files
#############################################################
""")

for ca_name in ca_names:

  sys.stdout.write('\nProcessing %s\n' % ca_name)
  ca = opensslcnf.getcadata(ca_name)
    
  # Create sub-directories
  CheckedMakeDir(ca.dir,perms=0755,uid=uidCAAdmin,gid=gidCAAdmin)
  CheckedMakeDir(ca.certs,perms=0755,uid=uidCAAdmin,gid=gidCAAdmin)
  CheckedMakeDir(ca.new_certs_dir,perms=0700,uid=uidCAAdmin,gid=gidCAAdmin)
  CheckedMakeDir(ca.crl_dir,perms=0755,uid=uidCAAdmin,gid=gidCAAdmin)

  if ca.pend_reqs_dir==ca.new_reqs_dir:
    CheckedMakeDir(ca.new_reqs_dir,perms=0370,uid=uidWWWRun,gid=gidCAAdmin)
  else:
    CheckedMakeDir(ca.pend_reqs_dir,perms=0370,uid=uidWWWRun,gid=gidMailDaemon)
    CheckedMakeDir(ca.new_reqs_dir,perms=0370,uid=uidMailDaemon,gid=gidCAAdmin)

  CheckedMakeDir(ca.old_reqs_dir,perms=0700,uid=uidCAAdmin,gid=gidCAAdmin)

  CheckedMakeDir(os.path.dirname(ca.certificate),perms=0755,uid=uidCAAdmin,gid=gidCAAdmin)
  if os.path.isfile(ca.certificate):
    # In any case we set permission and ownership of
    # CA certificate file if already existent
    os.chown(ca.certificate,uidCAAdmin,gidCAAdmin)
    os.chmod(ca.certificate,0444)

  CheckedMakeDir(os.path.dirname(ca.private_key),perms=0700,uid=uidCAAdmin,gid=gidCAAdmin)
  if os.path.isfile(ca.private_key):
    # In any case we set permission and ownership of
    # CA private key file if existent
    os.chown(ca.private_key,uidCAAdmin,gidCAAdmin)
    os.chmod(ca.private_key,0400)

  # database: database index file
  if not os.path.isfile(ca.database):
    sys.stdout.write('Creating database file %s\n' % (ca.database))
    file=open(ca.database,'w')
    file.write('')
    file.close()
  os.chown(ca.database,uidCAAdmin,gidCAAdmin)
  os.chmod(ca.database,0644)

  # serial: next serial number for issueing certificates
  if filenotvalid(ca.serial):
    sys.stdout.write('Creating serial file %s\n' % (ca.serial))
    file=open(ca.serial,'w')
    file.write('01\n')
    file.close()
  os.chown(ca.serial,uidCAAdmin,gidCAAdmin)
  os.chmod(ca.serial,0600)

os.setgid(gidCAAdmin)
os.setuid(uidCAAdmin)

sys.stdout.write("""
#############################################################
# create self-signed CA certs or certificate requests
#############################################################\n
Give passwords for each CAs here.
""")

subca = []

for ca_name in ca_names:

  sys.stdout.write('\nProcessing %s\n' % ca_name)
  ca = opensslcnf.getcadata(ca_name)
    
  if ca.signedby:
    # Add CA to list of sub-CAs to be signed late
    subca.append(ca_name)

  if filenotvalid('%s-req' % ca.certificate) and filenotvalid(ca.private_key):
    sys.stdout.write('Creating certificate request %s with private key %s.\n' % (ca.certificate,ca.private_key))
    if not ca.ca_reqfile:
      ca.ca_reqfile = ca.ca_x509_extfile
      if not ca.ca_reqfile:
        ca.ca_reqfile = opensslcnfname
    rc = os.system('%s req -config %s -new -outform pem -out %s-req -keyout %s' % \
                   (OpenSSLExec,ca.ca_reqfile,ca.certificate,ca.private_key))
    os.chmod(ca.private_key,0400)
    if rc:
      sys.stderr.write('Error %d creating CA cert request %s-req.\n' % (rc,ca.certificate))

  if filenotvalid(ca.certificate) and not ca.signedby:
    sys.stdout.write('How many days should this certificate be valid (minimum=%d, default=%d days): ' % (ca.default_days+1,2*ca.default_days+1))
    days = string.strip(sys.stdin.readline())
    if not days:
      days = 2*ca.default_days+1
    rc = os.system('%s x509 -req -inform pem -in %s-req -outform pem -out %s -signkey %s -days %s -extfile %s' % \
                   (OpenSSLExec,ca.certificate,ca.certificate,ca.private_key,days,ca.ca_x509_extfile))
    if rc:
      sys.stderr.write('Error %d self-signing CA cert %s.\n' % (rc,ca.certificate))


if subca:
  sys.stdout.write("""
#############################################################
# Create certs of sub-CAs
#############################################################\n
Use passwords of parent CAs here.\n
""")

  for ca_name in subca:
    sys.stdout.write('\nProcessing %s\n' % ca_name)
    # Get the sub-CA's config data
    subca = opensslcnf.getcadata(ca_name)
    # Check if signedby points to a valid CA section name
    if not subca.signedby in ca_names:
      sys.stderr.write('CA name "%s" given in signedby parameter of section [%s] not found.\n' % (subca.signedby,subca.sectionname))
      sys.exit(1)
    # Get the issuer's CA config data
    ca = opensslcnf.getcadata(subca.signedby)
    # Check if issuer's certificate and key files are present
    if filenotvalid(ca.certificate) or filenotvalid(ca.private_key):
      sys.stderr.write("""CA certificate or key file of issuer %s not found or zero-length.
      Check the files %s and %s.
      """ % (subca.signedby,ca.certificate,ca.private_key))
      sys.exit(1)
    # Check if issuer certificate is valid at current time
    gmt = time.time()
    ca_cert = openssl.cert.X509CertificateClass(ca.certificate)
    if gmt+86400*ca.default_days>ca_cert.notAfter_secs:
      sys.stderr.write("""Certificate of issueing parent CA "%s" is not valid until %s.
      You can either set parameter default_days<=%d in section [%s] or
      issue a new parent CA cert.
      """ % (ca.name,time.strftime('%Y-%m-%d %H:%M',time.gmtime(gmt+86400*ca.default_days)),(ca_cert.notAfter_secs-gmt)/86400,ca.sectionname))
      sys.exit(1)
    # Create the new sub-CA certificate if there's no older file in the way
    if filenotvalid(subca.certificate):
      sys.stdout.write('Creating sub-CA certificate %s with issuer "%s".\n' % (subca.certificate,ca.name))
      rc = os.system('%s x509 -req -inform pem -in %s-req -outform pem -out %s -CA %s -CAkey %s -CAserial %s -days %s -extfile %s' % \
                     (OpenSSLExec,subca.certificate,subca.certificate,ca.certificate,ca.private_key,ca.serial,ca.default_days,subca.ca_x509_extfile))
      if rc:
	sys.stderr.write('Error %d issueing CA cert %s.\n' % (rc,ca.certificate))
    else:
      sys.stdout.write('Sub-CA certificate file %s already exists. Skipping...\n' % (subca.certificate))

sys.stdout.write("""
#############################################################
# Verifying CA certs
#############################################################\n
""")

for ca_name in ca_names:

  ca = opensslcnf.getcadata(ca_name)

  if ca.signedby:
    if ca.signedby in ca_names:
      parentca = opensslcnf.getcadata(ca.signedby)
    else:
      parentca = None
      sys.stderr.write('CA name "%s" given in signedby parameter of section [%s] not found.\n' % (subca.signedby,subca.sectionname))
  else:
    parentca = ca

  if not (filenotvalid(ca.certificate) or filenotvalid(parentca.certificate)):

    sys.stdout.write('Verifying sub-CA certificate %s with issuer certificate %s.\n' % (ca.certificate,parentca.certificate))
    rc = os.system('%s verify -verbose -CAfile %s %s' % \
                   (OpenSSLExec,parentca.certificate,ca.certificate))
    if rc:
      sys.stderr.write('Error %d verifying CA cert %s.\n' % (rc,ca.certificate))

    ca_cert = openssl.cert.X509CertificateClass(ca.certificate)

    if not ca_cert.subject.has_key('CN'):
      sys.stderr.write('CA certificate %s has no CN attribute.\nThis might cause weird problems with some software.\n' % (ca.certificate))

    for subject_attr in ca_cert.subject.keys():
      if not charset.is_ascii(charset.asn12iso(ca_cert.subject[subject_attr])):
        sys.stderr.write('CA certificate %s has NON-ASCII attribute %s.\nThis might cause weird problems with some software.\n' % (ca.certificate,subject_attr))

  else:
    sys.stderr.write('Certificate file %s or %s not found.\n' % (ca.certificate,parentca.certificate))

