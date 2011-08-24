#!/usr/bin/python

########################################################################
# ldap2certs.py
# (c) by Michael Stroeder, michael@stroeder.com
# This simple script retrieves client certs from a LDAP repository
# and stores the fingerprint in a text mapping file for use with
# Postfix/TLS (see option relay_clientcert) and 
########################################################################

__version__ = '0.6.6'

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

  -v or --verbose
        Print debugging output to stdout

  --pylib=[directory]
        Specify directory containing the additonal Python modules.
        Default: 

  --host=[LDAP host]
	Specify an alternate host:port on which the ldap server
        is running.
	Default: localhost:389

  --basedn=[searchbase]
        Use searchbase as the starting point for the search
        instead of the default.
	Default: emtpy string

  --binddn=[binddn]
	Use binddn to bind to the LDAP directory.
	Default: cn=root[,searchbase]

  --bindpasswd=[password]
	Use password to bind to the LDAP directory. For security
	reasons it is better to set this with the env variable
	LDAP_PASSWD if you really have to provide the password
	in a non-interactive script.
	Default: emtpy string

  --searchfilter=[Python dict string]
	LDAP search filter for finding entries with
	certificate data.
	Default: (usercertificate;binary=*)

  --certdnfilter=[regex]
        Specify a filter as comma separated list of regular expressions
	for DNs of the certificates which should be sent to the LDAP host.
	E.g. C=DE,CN=.*,Email=.*@domain.my
	Default: Email=.*

  --outdir=[directory name]
        Directory where to store the client cert files
	and symbolic links ([hash value].0).
	If not defined no client cert files are written.

  --rcc_filename=[path name]
        Path name of lookup table file.
	(parameter relay_clientcerts in main.cf of Postfix/TLS)
	If not defined the table is not written.

  --rcc_delimiter=(:|_)
        Character used as delimiter for fingerprint string
	Default: ":"

  --replace
        Replace existing files (append or add otherwise)

""" % (script_name,script_name))
  if ErrorMsg:
    sys.stderr.write('Error: %s\n' % ErrorMsg)
  sys.exit(ErrorCode)

script_name=sys.argv[0]

try:
  options,args=getopt.getopt(
    sys.argv[1:],'vh',
    [
      'help',
      'verbose',
      'pylib=',
      'host=',
      'basedn=',
      'binddn=',
      'bindpasswd=',
      'searchfilter=',
      'outdir=',
      'rcc_filename=',
      'rcc_delimiter=',
      'replace'
    ]
  )
except getopt.error,e:
  PrintUsage(str(e))

if findoption(options,'-h')!=() or findoption(options,'--help')!=():
  PrintUsage()

if findoption(options,'-v')!=() or findoption(options,'--verbose')!=():
  pass
else:
  sys.stdout.close()
  sys.stdout = open('/dev/null','w')

if findoption(options,'--pylib')!=():
  pylib = findoption(options,'--pylib')[1]
  if not os.path.exists(pylib) or not os.path.isdir(pylib):
    PrintUsage('Modules directory %s not found or is not a directory!' % (pylib))
  sys.path.append(pylib)

import charset,ldap,certhelper

if findoption(options,'--host')!=():
  ldap_host = findoption(options,'--host')[1]
else:
  ldap_host = 'localhost:389'

if findoption(options,'--basedn')!=():
  basedn = findoption(options,'--basedn')[1]
else:
  basedn = ''

if findoption(options,'--binddn')!=():
  binddn = findoption(options,'--binddn')[1]
else:
  if basedn:
    binddn = 'cn=root,%s' % basedn
  else:
    binddn = 'cn=root'

if findoption(options,'--bindpasswd')!=():
  bindpasswd = findoption(options,'--bindpasswd')[1]
else:
  if os.environ.has_key('LDAP_PASSWD'):
    bindpasswd = os.environ.get['LDAP_PASSWD']
  else:
    from getpass import getpass
    bindpasswd = getpass()

if findoption(options,'--searchfilter')!=():
  searchfilter = charset.iso2utf(findoption(options,'--searchfilter')[1])
else:
  searchfilter = '(usercertificate;binary=*)'

if findoption(options,'--replace')!=():
  replace = 1
else:
  replace = 0
sys.stderr.write('replace=%s\n' % replace)

rcc_filemode = {0:'a',1:'w'}
cert_filemode = {0:'w',1:'w'}

if findoption(options,'--rcc_filename')!=():
  rcc_filename = findoption(options,'--rcc_filename')[1]
  sys.stdout.write('rcc_filename=%s\n' % rcc_filename)
  rcc_file = open(rcc_filename,rcc_filemode[replace])
else:
  rcc_filename = None

if findoption(options,'--rcc_delimiter')!=():
  rcc_delimiter = findoption(options,'--rcc_delimiter')[1]
else:
  rcc_delimiter = ':'

sys.stdout.write('rcc_delimiter=%s\n' % rcc_delimiter)

if findoption(options,'--outdir')!=():
  outdir = findoption(options,'--outdir')[1]
  if not os.path.exists(outdir) or not os.path.isdir(outdir):
    PrintUsage('Directory %s not found or is not a directory!' % (outdir))
else:
  outdir = None

try:
  l = ldap.open(ldap_host)
except:
  exc_obj,exc_value,exc_traceback = sys.exc_info()
  sys.stderr.write('Error %d connecting to %s: %s\n' % (exc_value[0],ldap_host,exc_value[1]))
  sys.exit(1)

try:
  l.bind_s(binddn,bindpasswd,ldap.AUTH_SIMPLE)
except:
  exc_obj,exc_value,exc_traceback = sys.exc_info()
  sys.stderr.write('Unable to bind as "%s" to "%s":\n%s\n' % (binddn,ldap_host,exc_value))
  sys.exit(1)

try:
  ldap_msgid = l.search(
    basedn,
    ldap.SCOPE_SUBTREE,
    searchfilter,
    ['cn','mail','usercertificate','usersmimecertificate','usercertificate;binary','usersmimecertificate;binary'],
    0
  )
except ldap.NO_SUCH_OBJECT:
  result_dnlist = []
except ldap.FILTER_ERROR:
  sys.stderr.write('Bad search filter %s.\n' % charset.utf2iso(searchfilter))
  sys.exit(1)
except ldap.SIZELIMIT_EXCEEDED:
  sys.stderr.write('Sizelimit exceeded. Please refine search.\n')
  sys.exit(1)
except ldap.NO_SUCH_OBJECT:
  sys.stderr.write('No search results with filter %s.\n' % charset.utf2iso(searchfilter))
  sys.exit(1)
except ldap.error:
  exc_obj,exc_value,exc_traceback = sys.exc_info()
  sys.stderr.write('LDAP exception %(desc)s: %(info)s.\n' % exc_value)
  sys.exit(1)
#except:
#  exc_obj,exc_value,exc_traceback = sys.exc_info()
#  sys.stderr.write('Unhandled exception: %s.\n' % exc_value)
#  sys.exit(1)

result_type,result_data = l.result(ldap_msgid,0)
if not result_type in ['RES_SEARCH_ENTRY','RES_SEARCH_RESULT']:
  l.abandon(ldap_msgid)
  sys.stderr.write('Wrong result type: "%s"' % (result_type))
  sys.exit(1)

# Retrieve the search results
while result_data:

  # Process found entries
  for dn,data in result_data:

    sys.stdout.write('Processing entry "%s".\n' % (charset.utf2iso(dn)))
    if data.has_key('usercertificate'):
      pass

    elif data.has_key('usersmimecertificate'):
      pass

    elif data.has_key('usercertificate;binary'):

      sys.stdout.write('%d DER-encoded certificate(s) found.\n' % (len(data['usercertificate;binary'])))

      # Process all certificates in attribute
      for cert_der in data['usercertificate;binary']:

        cert_md5fingerprint = certhelper.MD5Fingerprint(cert_der,':')

        if rcc_filename:
          # append fingerprint to rcc_filename
	  rcc_name = data.get('mail',data.get('cn',[dn]))[0]
          rcc_file.write('%s %s\n' % (string.replace(cert_md5fingerprint,':',rcc_delimiter),rcc_name))

        if outdir:
          cert_pem = certhelper.der2pem(cert_der)
	  cert_pem_filename = os.path.join(outdir,'%s.pem' % string.replace(cert_md5fingerprint,':','_'))
          if replace or not os.path.isfile(cert_pem_filename):
            cert_pem_file = open(cert_pem_filename,cert_filemode[replace])
            cert_pem_file.write(cert_pem)
	    cert_pem_file.close()
	    sys.stdout.write('Certificate file %s written.\n' % (cert_pem_filename))
	  else:
	    sys.stdout.write('Certificate file %s already exists.\n' % (cert_pem_filename))

    elif data.has_key('usersmimecertificate;binary'):
      pass

    else:
      sys.stdout.write('No certificate data.\n')

  # Get next result
  result_type,result_data = l.result(ldap_msgid,0)

l.unbind_s()

