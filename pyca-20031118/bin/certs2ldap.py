#!/usr/bin/python

"""
certs2ldap.py - Upload all EE certificates on LDAP server
(c) by Michael Stroeder, michael@stroeder.com
"""

__version__ = '0.6.6'

import sys, string, os, getopt

ldap_attrtype = {
  'ST':'st',
  'Email':'mail',
  'emailAddress':'mail',
  'E':'mail',
  'L':'l',
  'O':'o',
  'OU':'ou',
  'CN':'cn',
}

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

  --filtertemplate=[Python dict string]
	A Python string used as template for searching the
	LDAP entries of certificate owners.
	E.g. (&(cn=%%(CN)s)(mail=%%(Email)s))
	Default: (mail=%%(Email)s)

  --certdnfilter=[regex]
        Specify a filter as comma separated list of regular expressions
	for DNs of the certificates which should be sent to the LDAP host.
	E.g. C=DE,CN=.*,Email=.*@domain.my
	Default: Email=.*

  --objectclasses=[objectClass]
        Add objectclass: [objectClass] to the entry. Might be
        a comma-separated list for specifying multiple object classes.

  --replace
        Replace existing userCertificate;binary attributes

  --create
        Create LDAP entries if no entry for a user certificate
        was found.

  --dntemplate=[Python dict string]
	A Python string used as template for the distinguished
	name of LDAP entries to be created.
	E.g. cn=%%(CN)s+mail=%%(Email)s,ou=Testing,dc=stroeder,dc=com

""" % (script_name,script_name))
  if ErrorMsg:
    sys.stderr.write('Error: %s\n' % ErrorMsg)
  sys.exit(ErrorCode)

script_name=sys.argv[0]

try:
  options,args=getopt.getopt(
    sys.argv[1:],'h',
    [
      'help',
      'config=',
      'pycalib=',
      'host=',
      'basedn=',
      'binddn=',
      'bindpasswd=',
      'filtertemplate=',
      'certdnfilter=',
      'objectclasses=',
      'replace',
      'create',
      'dntemplate='
    ]
  )
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
  sys.exit(1)

if findoption(options,'--pycalib')!=():
  pycalib = findoption(options,'--pycalib')[1]
else:
  pycalib = os.environ.get('PYCALIB','/usr/local/pyca/pylib')

if not os.path.exists(pycalib) or not os.path.isdir(pycalib):
  PrintUsage('Directory %s with pyCA modules not found!' % (pycalib))

sys.path.append(pycalib)

try:
  import ldap
except ImportError:
  PrintUsage('python-ldap module not found.' % (pycalib))
  sys.exit(1)

try:
  import openssl,charset
except ImportError:
  PrintUsage('pyCA modules not found in directory %s.' % (pycalib))
  sys.exit(1)

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

delete_reason = {openssl.db.DB_TYPE_EXP:'expired',openssl.db.DB_TYPE_REV:'revoked'}

pyca_section = opensslcnf.data.get('pyca',{})
openssl.bin_filename = pyca_section.get('OpenSSLExec','/usr/local/ssl/bin/openssl')
if not os.path.isfile(openssl.bin_filename):
  sys.stderr.write('Did not find OpenSSL executable %s.\n' % (openssl.bin_filename))
  sys.exit(1)

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
    sys.stdout.write('Enter password for bind DN "%s".\n' % (binddn))
    bindpasswd = getpass()

if findoption(options,'--filtertemplate')!=():
  filtertemplate = findoption(options,'--filtertemplate')[1]
else:
  filtertemplate = r'(mail=%(Email)s)'

if findoption(options,'--objectclasses')!=():
  objectclasses = map(
    string.strip,
    map(
      None,string.split(findoption(options,'--objectclasses')[1],',')
    )
  )
else:
  objectclasses = None

replace = findoption(options,'--replace')!=()

if findoption(options,'--certdnfilter')!=():
  certdnfilterlist = string.split(findoption(options,'--certdnfilter')[1],',')
  certdnfilter = {}
  for i in certdnfilterlist:
    attr,filter = string.split(i,'=',1)
    if filter:
      certdnfilter[attr]=filter
else:
  certdnfilter = {'Email':'.*'}

create = findoption(options,'--create')!=()

if findoption(options,'--dntemplate')!=():
  dntemplate = findoption(options,'--dntemplate')[1]
else:
  dntemplate = r'mail=%(Email)s,'+basedn

print repr(dntemplate)

# FIX ME!!!
# This should be surrounded by a nice try: except: clause
# which catches specific exceptions and outputs
# nicer error messages.
l = ldap.open(ldap_host)
l.bind_s(binddn,bindpasswd,ldap.AUTH_SIMPLE)

ca_names = opensslcnf.sectionkeys.get('ca',[])

old_db_filenames = []

for ca_name in ca_names:

  sys.stdout.write('*** Processing %s ***\n\n' % (ca_name))

  ca = opensslcnf.getcadata(ca_name)

  # Ist der Zertifikattyp 'S/MIME for client use' ?
  if ca.isclientcert() and \
     not ca.database in old_db_filenames and \
     os.path.isfile(ca.database):

    old_db_filenames.append(ca.database)

    # Anfrage starten
    certs_found = openssl.db.GetEntriesbyDN(ca.database,certdnfilter,casesensitive=1,onlyvalid=0)

    for cert_entry in certs_found:

      certdn = charset.asn12iso(cert_entry[openssl.db.DB_name])
      certdndict = openssl.db.SplitDN(charset.iso2utf(certdn))
      ldap_filter = filtertemplate % certdndict
      try:
        ldap_result = l.search_s(
	  basedn,
	  ldap.SCOPE_SUBTREE,
	  ldap_filter,
	  ['objectclass','userCertificate;binary','userSMIMECertificate;binary'],
	  0
	)
      except ldap.NO_SUCH_OBJECT:
  	sys.stdout.write('Certificate subject "%s" not found with filter "%s".\n' % (certdn,ldap_filter))
	ldap_result=[]
      except:
	exc_obj,exc_value,exc_traceback = sys.exc_info()
	sys.stderr.write('Unexpected error during searching with filter "%s":\n%s\n' % (ldap_filter,exc_value))
	sys.exit(1)

      if ldap_result:

        # Read certificate data
        certfilename = os.path.join(ca.certs,'%s.pem' % (cert_entry[openssl.db.DB_serial]))
	cert = openssl.cert.X509CertificateClass(certfilename)
	local_cert = cert.readcertfile('der')

	for entry in ldap_result:

          ldap_dn = entry[0]

          old_objectclasses = {}
          for oc in entry[1].get('objectClass',entry[1].get('objectclass',[])):
            old_objectclasses[string.lower(oc)] = None

          existing_usercert_attrtype = None
          for a in [
            'userCertificate;binary','userCertificate',
            'usercertificate;binary','usercertificate',
          ]:
            if entry[1].has_key(a):
              existing_usercert_attrtype = a
              break

          old_usercertificate_attr = {}
          if existing_usercert_attrtype!=None:
            for ldap_cert in entry[1][existing_usercert_attrtype]:
              old_usercertificate_attr[ldap_cert] = None

          ldap_modlist = []

          if cert_entry[openssl.db.DB_type]==openssl.db.DB_TYPE_VAL:

	    if existing_usercert_attrtype is None:
              # Add new certificate attribute
              ldap_modlist.append((ldap.MOD_ADD,'userCertificate;binary',[local_cert]))
   	      sys.stdout.write('Adding new certificate attribute usercertificate;binary with certificate serial %s of LDAP entry "%s".\n' % (cert_entry[openssl.db.DB_serial],charset.utf2iso(ldap_dn)))
            elif replace:
              # Replace existing certificate attribute
              ldap_modlist.append((ldap.MOD_DELETE,existing_usercert_attrtype,None))
              ldap_modlist.append((ldap.MOD_ADD,existing_usercert_attrtype,[local_cert]))
   	      sys.stdout.write('Replacing attribute %s of entry %s with certificate serial %s.\n' % (
                  existing_usercert_attrtype,
		  charset.utf2iso(ldap_dn),
		  cert_entry[openssl.db.DB_serial]
	        )
	      )
	    elif not old_usercertificate_attr.has_key(local_cert):
              # Add new certificate attribute value
              ldap_modlist.append((ldap.MOD_DELETE,existing_usercert_attrtype,None))
              ldap_modlist.append((ldap.MOD_ADD,existing_usercert_attrtype,old_usercertificate_attr.keys()+[local_cert]))
   	      sys.stdout.write(
                'Adding certificate with certificate serial %s to existing attribute %s of LDAP entry "%s".\n' % (
                  cert_entry[openssl.db.DB_serial],
                  existing_usercert_attrtype,
                  charset.utf2iso(ldap_dn)
                )
              )
            else:
   	      sys.stdout.write('Leaving attribute %s of entry %s untouched.\n' % (
                  existing_usercert_attrtype,
		  charset.utf2iso(ldap_dn)
	        )
	      )

            if ldap_modlist and objectclasses:
              # New object classes were specified at command-line
              # => add to modify list if necessary
              new_objectclasses = []
              for oc in objectclasses:
                if not old_objectclasses.has_key(string.lower(oc)):
                  new_objectclasses.append(oc)
              if new_objectclasses:
                ldap_modlist.append((ldap.MOD_ADD,'objectClass',new_objectclasses))


          elif (cert_entry[openssl.db.DB_type]==openssl.db.DB_TYPE_EXP) or \
	       (cert_entry[openssl.db.DB_type]==openssl.db.DB_TYPE_REV):

            sys.stdout.write('Certificate (serial %s) %s.\n' % (cert_entry[openssl.db.DB_serial],delete_reason[cert_entry[openssl.db.DB_type]]))

            if old_usercertificate_attr.has_key(local_cert):
              del old_usercertificate_attr[local_cert]
              sys.stdout.write('Deleting certificate with certificate serial %s from attribute usercertificate;binary of LDAP entry "%s".\n' % (cert_entry[openssl.db.DB_serial],charset.utf2iso(ldap_dn)))
              ldap_modlist.append((ldap.MOD_REPLACE,existing_usercert_attrtype,old_usercertificate_attr.keys()))

            if ldap_modlist and objectclasses:
              new_objectclasses = []
              for oc in objectclasses:
                if old_objectclasses.has_key(string.lower(oc)):
                  new_objectclasses.append(oc)
              if new_objectclasses:
                ldap_modlist.append((ldap.MOD_DELETE,'objectClass',new_objectclasses))


          # Do modifications on directory if modlist is not empty
          if ldap_modlist:
	    try:
	      l.modify_s(ldap_dn,ldap_modlist)
	    except ldap.NO_SUCH_OBJECT:
	      sys.stderr.write('No such object "%s": Probably a parent entry is missing.\n' % (
	          charset.utf2iso(ldap_dn)
	        )
	      )
	    except ldap.INSUFFICIENT_ACCESS,e:
	      sys.stderr.write('You are not allowed to modify entry "%s": %s.\n' % (
	          charset.utf2iso(ldap_dn),str(e)
	        )
	      )
	    except ldap.LDAPError,e:
	      sys.stderr.write('LDAPError: %s.\n' % str(e))

      else:

        if cert_entry[openssl.db.DB_type]==openssl.db.DB_TYPE_VAL:

          if create:

            # Read certificate data
            certfilename = os.path.join(ca.certs,'%s.pem' % (cert_entry[openssl.db.DB_serial]))
	    cert = openssl.cert.X509CertificateClass(certfilename)
	    local_cert = cert.readcertfile('der')

            ldap_dn = dntemplate % certdndict

            ldap_modlist = [
              ('objectClass',['person','organizationalPerson','inetOrgPerson']),
              ('userCertificate;binary',[local_cert]),
              ('sn',['-'])
            ]
            for k in certdndict.keys():
              try:
                ldap_modlist.append((ldap_attrtype[k],certdndict[k]))
              except KeyError:
                pass

	    try:
#              print ldap_modlist
	      l.add_s(ldap_dn,ldap_modlist)
	    except ldap.NO_SUCH_OBJECT:
	      sys.stderr.write('No such object "%s": Probably a parent entry is missing.\n' % (
	          charset.utf2iso(ldap_dn)
	        )
	      )
	    except ldap.INSUFFICIENT_ACCESS,e:
	      sys.stderr.write('You are not allowed to add entry "%s": %s.\n' % (
	          charset.utf2iso(ldap_dn),str(e)
	        )
	      )
	    except ldap.LDAPError,e:
	      sys.stderr.write('LDAPError: %s.\n' % str(e))
            else:
   	      sys.stdout.write('Added new entry "%s" for certificate serial %s.\n' % (charset.utf2iso(ldap_dn),cert_entry[openssl.db.DB_serial]))
            
          else:
            sys.stderr.write('No entry found with filter "%s" for %s.\n' % (ldap_filter,certdn))     

l.unbind_s()
