#!/usr/bin/python

########################################################################
# print-ca-certs.py
# (c) by Michael Stroeder, michael@stroeder.com
########################################################################

__version__ = '0.6.6'

########################################################################
# This simple script prints all CA certs on stdout.
# This is intended to generate a authentic printout of the fingerprints
# on the private CA system.
# Choose the option --html to generate nicer formatted HTML-output
# instead of the default textual output in ISO-8859-1.
########################################################################


import sys, string, os, getopt

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

  --html
        Generate nicer formatted HTML output

""" % (script_name,script_name))
  if ErrorMsg:
    sys.stderr.write('Error: %s\n' % ErrorMsg)
  sys.exit(ErrorCode)

script_name=sys.argv[0]

try:
  options,args=getopt.getopt(sys.argv[1:],'h',['help','config=','pycalib=','html'])
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
  import openssl, charset, htmlbase
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

htmlmode = findoption(options,'--html')!=()

if htmlmode:

  #HTML mode

  sys.stdout.write('<HTML>\n<HEAD>\n<TITLE>CA certs</TITLE>\n</HEAD>\n<BODY>\n<CENTER>\n')

  for ca_name in ca_names:

    ca = opensslcnf.getcadata(ca_name)

    if os.path.isfile(ca.certificate):

      # Parse certificate textual output
      cacert = openssl.cert.X509CertificateClass(ca.certificate)
      sys.stdout.write('<H2>%s</H2>%s<P>' % (ca_name,cacert.htmlprint()))

  sys.stdout.write('</CENTER>\n</BODY>\n</HTML>\n')


else:

  # Text mode

  for ca_name in ca_names:

    ca = opensslcnf.getcadata(ca_name)

    if os.path.isfile(ca.certificate):

      # Parse certificate textual output
      cacert = openssl.cert.X509CertificateClass(ca.certificate)

      # Convert character sets
      subject,issuer = {},{}
      for attr in ['CN','Email','OU','O','L','ST','C']:
        subject[attr] = string.strip(charset.asn12iso(cacert.subject.get(attr,'')))
        issuer[attr]  = string.strip(charset.asn12iso(cacert.issuer.get(attr,'')))

      sys.stdout.write('Subject:\nCommon Name: "%(CN)s"\nOrganizational Unit: "%(OU)s"\nOrganization: "%(O)s"\nLocation: "%(L)s"\nState/Province: "%(ST)s"\nCountry: "%(C)s"\n\n' % (subject))
      sys.stdout.write('Issuer:\nCommon Name: "%(CN)s"\nOrganizational Unit: "%(OU)s"\nOrganization: "%(O)s"\nLocation: "%(L)s"\nState/Province: "%(ST)s"\nCountry: "%(C)s"\n\n' % (issuer))
      sys.stdout.write('Serial: %s\n' % (cacert.serial))
      sys.stdout.write('Validity: from %s until %s\n' % (cacert.notBefore,cacert.notAfter))
      sys.stdout.write('Hash: %s\n' % (cacert.hash))
      sys.stdout.write('SHA-1 Fingerprint: %s\n' % (cacert.getfingerprint('sha1')))
      sys.stdout.write('MD5   Fingerprint: %s\n' % (cacert.getfingerprint('md5')))
      sys.stdout.write('\n%s\n\n' % (72*'-'))
