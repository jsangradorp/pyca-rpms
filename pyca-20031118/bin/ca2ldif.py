#!/usr/bin/python

########################################################################
# ca2ldif.py
# (c) by Michael Stroeder, michael@stroeder.com
########################################################################

__version__ = '0.6.6'

########################################################################
# This simple script generates a LDIF file containing all CA certs
# and CRLs.
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
	Default: /usr/local/pyca/pylib

  --out=[pathname]
	Pathname of LDIF file for output
	Default: stdout

  --dntemplate=[Python dict string]
	A Python string used as template for building LDAP
	Distinguished Names E.g. cn=%%(CN)s,ou=TestCA,o=My company,c=DE
	Default: cn=%%(CN)s

  --crl
        Add CRLs to entries.

""" % (script_name,script_name))
  if ErrorMsg:
    sys.stderr.write('Error: %s\n' % ErrorMsg)
  sys.exit(ErrorCode)

script_name=sys.argv[0]

try:
  options,args=getopt.getopt(sys.argv[1:],'h',['help','config=','pycalib=','out=','dntemplate=','crl'])
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
  PrintUsage('Module directory %s does not exist or is no directory.' % (pycalib))
  sys.exit(1)

sys.path.append(pycalib)

try:
  import openssl, charset, ldif, ldapbase
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

create_crls = findoption(options,'--crl')!=()

pyca_section = opensslcnf.data.get('pyca',{})
openssl.bin_filename = pyca_section.get('OpenSSLExec','/usr/local/ssl/bin/openssl')
if not os.path.isfile(openssl.bin_filename):
  sys.stderr.write('Did not find OpenSSL executable %s.\n' % (openssl.bin_filename))
  sys.exit(1)

if findoption(options,'--out')!=():
  ldiffile = open(findoption(options,'--out')[1],'w')
else:
  ldiffile = sys.stdout

if findoption(options,'--dntemplate')!=():
  dntemplate = findoption(options,'--dntemplate')[1]
else:
  dntemplate = r'cn=%(CN)s'

ca_names = opensslcnf.sectionkeys.get('ca',[])
ca_dn_dict = {}

for ca_name in ca_names:

  ca = opensslcnf.getcadata(ca_name)

  if os.path.isfile(ca.certificate):

    cacert = openssl.cert.X509CertificateClass(ca.certificate)

    ca_dn = charset.iso2utf(charset.t612iso(dntemplate % (cacert.subject)))
    if ca_dn_dict.has_key(ca_dn):
      sys.stderr.write('Warning: DN of %s conflicts with %s.\n' % (ca_name,ca_dn_dict[ca_dn]))
    else:
      ca_dn_dict[ca_dn]=ca_name

    if ldapbase.dn_regex.match(ca_dn):
      ca_entry = {'objectclass':['top','certificationAuthority']}
      ca_entry['cACertificate;binary'] = [cacert.readcertfile('der')]

      if create_crls:
	if os.path.isfile(ca.crl):

          cacrl = openssl.cert.CRLClass(ca.crl)
          ca_entry['certificateRevocationList;binary'] = [cacrl.readcertfile('der')]
          ca_entry['authorityRevocationList;binary'] = [cacrl.readcertfile('der')]

	else:
          sys.stderr.write('Warning: CRL file %s not found.\n' % (ca.crl))
          certificateRevocationList_binary=''

      ldiffile.write(ldif.CreateLDIF(ca_dn,ca_entry,['cACertificate;binary','certificateRevocationList;binary']))
      ldiffile.write('\n')

    else:
      sys.stderr.write('Warning: DN "%s" is not a valid DN.\nCheck parameter --dntemplate="%s".\n' % (ca_dn,dntemplate))
      cACertificate_binary=''

  else:
    sys.stderr.write('Warning: CA certificate file %s not found.\n' % (ca.certificate))
    cACertificate_binary=''

ldiffile.close()

