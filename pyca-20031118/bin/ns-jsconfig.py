#!/usr/bin/python

########################################################################
# ns-jscertconfig.py
# (c) by Michael Stroeder, michael@stroeder.com
########################################################################

__version__ = '0.6.6'

########################################################################
# This simple script generates Javascript code containing all CA certs
# for a netscape.cfg
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

  --nssecconf=[pathname]
	Pathname of Javascript file to output containing all CA certs
	for inclusion in netscape.cfg.
	The trust parameters are marked according to nsCertType.
	Self-signed certificates are marked with flag 'C' otherwise 'c'.
	Default: stdout

  --friendlynametemplate=[Python dict string]
	A Python string used as template for building friendly
	CA names. E.g. TestCA %%(CN)s %%(O)s
	Default: %%(CN)s

""" % (script_name,script_name))
  if ErrorMsg:
    sys.stderr.write('Error: %s\n' % ErrorMsg)
  sys.exit(ErrorCode)

script_name=sys.argv[0]

try:
  options,args=getopt.getopt(sys.argv[1:],'h',['help','config=','pycalib=','nssecconf=','friendlynametemplate='])
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

if findoption(options,'--nssecconf')!=():
  nssecconf = open(findoption(options,'--nssecconf')[1],'w')
else:
  nssecconf = sys.stdout

if findoption(options,'--friendlynametemplate')!=():
  friendlynametemplate = findoption(options,'--friendlynametemplate')[1]
else:
  friendlynametemplate = '%(CN)s'

ca_names = opensslcnf.sectionkeys.get('ca',[])

nssecconf.write("""with (SecurityConfig) {
function pyCACertConfig() {\n
""")

for ca_num in range(len(ca_names)):

  ca_name = ca_names[ca_num]

  ca = opensslcnf.getcadata(ca_name)

  if os.path.isfile(ca.certificate):

    cacert = openssl.cert.X509CertificateClass(ca.certificate)

    # Append CA certificate file to Javascript configuration file
    cacertfile = open(ca.certificate,'r')
    certbuf = []
    line = cacertfile.readline()
    while line:
      certbuf.append('"%s\\n"' % (string.strip(line)))
      line = cacertfile.readline()
    cacertfile.close()

    if cacert.issuer==cacert.subject:
      ns_trustflag = 'C'
    else:
      ns_trustflag = 'c'

    if ca.nsCertType:
      ns_trustparams = ['','','']
      if type(ca.nsCertType)==types.ListType:
        nsCertType = ca.nsCertType
      else:
        nsCertType = [ca.nsCertType]
      for nstype in nsCertType:
	if nstype in ['server','sslCA']:
	  ns_trustparams[0]=ns_trustflag
	if nstype in ['email','client','emailCA']:
	  ns_trustparams[1]=ns_trustflag
	if nstype in ['objsign','objCA']:
	  ns_trustparams[2]=ns_trustflag
    else:
      ns_trustparams = [ns_trustflag,ns_trustflag,ns_trustflag]

    nssecconf.write("""CE_addCert%d = new Certificate(
%s);
if ( ! CE_addCert%d.isPerm ) {
certDB.addCert(CE_addCert%d, "%s", "%s");
}
""" % (ca_num,string.join(certbuf,'+\n'),ca_num,ca_num,string.join(ns_trustparams,','),friendlynametemplate % cacert.subject))
      
  else:
    sys.stderr.write('Warning: CA certificate file %s not found.\n')

nssecconf.write("""}
pyCACertConfig()

}""")

nssecconf.close()

