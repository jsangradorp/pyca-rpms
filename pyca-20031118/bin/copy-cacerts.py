#!/usr/bin/python

########################################################################
# copy-cacerts.py
# (c) by Michael Stroeder, michael@stroeder.com
########################################################################

__version__ = '0.6.6'

########################################################################
# This simple script copies either
# - all CA certs into a single PEM file
#   (intended for use ApacheSSL SSLCACertificateFile) or
# - a directory with appropriate hash symlinks to the CA cert files
#   (intended for use ApacheSSL SSLCACertificatePath).
########################################################################


import sys, string, os, getopt, types, shutil

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
	Default: /etc/openssl/openssl.cnf

  --pycalib=[directory]
        Specify directory containing the pyCA modules
        You may also use env variable PYCALIB.
	Default: /usr/local/pyca/pylib

  --certfile=[pathname of output PEM file]
	Pathname of output PEM file containing all CA certs

  --certdir=[directoryname]
	Target directory for all CA certs. The CA certs are copied
	to files named like the subject DN and symbolic links are
	created like cacert.pem -> certhash.0.
	Default is to use the current directory.

If you do not specify any of these options --certfile=./ca-certs.pem
is assumed.

""" % (script_name,script_name))
  if ErrorMsg:
    sys.stderr.write('Error: %s\n' % ErrorMsg)
  sys.exit(ErrorCode)

script_name=sys.argv[0]

try:
  options,args=getopt.getopt(sys.argv[1:],'h',['help','config=','pycalib=','certdir=','certfile='])
except getopt.error,e:
  PrintUsage(str(e))

if findoption(options,'-h')!=() or findoption(options,'--help')!=():
  PrintUsage(script_name)

if findoption(options,'--config')!=():
  opensslcnfname = findoption(options,'--config')[1]
else:
  opensslcnfname = os.environ.get('OPENSSL_CONF','/etc/openssl/openssl.cnf')

if not os.path.isfile(opensslcnfname):
  PrintUsage('Config file %s not found.' % (opensslcnfname))
  sys.exit(1)

if findoption(options,'--pycalib')!=():
  pycalib = findoption(options,'--pycalib')[1]
else:
  pycalib = os.environ.get('PYCALIB','/usr/local/pyca/pylib')

if not os.path.exists(pycalib) or not os.path.isdir(pycalib):
  PrintUsage('Module directory %s not exists or not a directory.' % (pycalib))
  sys.exit(1)

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

if findoption(options,'--certfile')!=():
  certfilename = findoption(options,'--certfile')[1]
  certfile = open(certfilename,'w')
else:
  certfilename = ''

if findoption(options,'--certdir')!=():
  certdir = findoption(options,'--certdir')[1]
  if not os.path.exists(certdir) or not os.path.isdir(certdir):
    PrintUsage('Directory %s not exists or not a directory.' % (certdir))
    sys.exit(1)
else:
  certdir = ''

if not certfilename and not certdir:
  # Set at least one usable default
  certfilename = './ca-certs.pem'
  certfile = open(certfilename,'w')

ca_names = opensslcnf.sectionkeys.get('ca',[])

for ca_num in range(len(ca_names)):

  ca_name = ca_names[ca_num]

  ca = opensslcnf.getcadata(ca_name)

  if os.path.isfile(ca.certificate):

    cacert = openssl.cert.X509CertificateClass(ca.certificate)

    # Copy the CA certificate file to directory
    if certdir:

      # Convert character sets
      for dict in [cacert.issuer,cacert.subject]:
	for attr in dict.keys():
          dict[attr] = charset.asn12iso(dict[attr])

      # New filename for CA cert
      cacert_filename = '%(CN)s_%(OU)s_%(O)s_%(L)s_%(ST)s_%(C)s' % (cacert.subject) + os.path.splitext(ca.certificate)[1]
      # Copy the file
      shutil.copyfile(ca.certificate,os.path.join(certdir,cacert_filename))
      # Create appropriate symlink
      symlinkname = os.path.join(certdir,'%s.0' % (cacert.hash))
      try:      
        os.symlink(cacert_filename,symlinkname)
      except OSError:
        sys.stderr.write('Warning: Could not create symbolic link.\n')

    # Append CA certificate file to single certificate file
    if certfilename:
      cacertfile = open(ca.certificate,'r')
      buf = cacertfile.read()
      while buf:
        certfile.write(buf)
        buf = cacertfile.read()
      cacertfile.close()
    
  else:
    sys.stderr.write('Warning: CA certificate file %s not found.\n')

if certfilename:
  certfile.close()

