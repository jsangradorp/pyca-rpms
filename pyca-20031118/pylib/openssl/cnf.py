#######################################################################
# openssl.cnf.py
# (c) by Michael Stroeder, michael.stroeder@propack-data.de
########################################################################
# Modul fuer den Zugriff auf die SSLeay-Konfigurationsdatei
# openssl.cnf
########################################################################

########################################################################
# Ab hier gibt es nix mehr zu konfigurieren
########################################################################

import sys,types,string,re,charset

__version__ = '0.6.6'

########################################################################
# Funktion GetAllSections() 
# Eingabe:
#   keine
# Ausgabe:
#   Dictionary mit Abschnittsnamen als Index und Dictionaries der
#   einzelnen Abschnitte als Feldelemente
#   {}, falls Konfigurationsdatei leer
# Anmerkung:
#   Fuer Konfigurationseintraege ausserhalb eines Abschnittes wird der
#   Pseudo-Abschnittsnamen '_' gesetzt.
########################################################################

def GetAllSections(filename):

  keys = {'_':[]}
  result = {'_':{}}

  # parameters not within a section will be stored in dummy section "_"
  section_name = '_'

  # regular exp for a line defining a section name
  issection_re=re.compile(r'^\s*\[\s*\w+\s*\]\s*(#)*.*')

  # regular exp for extracting a section name in a section line
  section_name_re=re.compile(r'\[\s*\w+\s*\]')

  # regular exp for a syntactically correct line defining a parameter
  # e.g. name = "parameter1",parameter2 # comment
  isparamline_re=re.compile(r'^(\d+.)*[\w_]+\s*=.*[\s#]*.*')

  # regular exp for extracting a parameter [num.]name in a parameter line
  paramline_numname_re=re.compile(r'(\d+.)*[\w_]+')

  # regular exp for extracting all parameter values from value incl. comment part
  onevalue_regex = r'(´.*?´|".*?"|[^:^,^#]*[^:^,^#^\s]|[^:^,^#]+:([^:^,^#]*[^:^,^#^\s]+|".*?"|´.*?´))'
  paramline_valuepart_re=re.compile(onevalue_regex+r'+(,'+onevalue_regex+')*\s*(#)*')

  # regular exp for splitting all values from value part
  paramline_valuesplit_re=re.compile('%s' % (onevalue_regex))

  # regular exp for testing if param is quoted
  isquoted_re=re.compile('(%s|%s|%s)' % ('´.*´','".*"',"'.*'"))
  
  # Open config file
  cnf_file = open(filename,'r')

  # Read first line from file
  line = cnf_file.readline()
  linenum = 0
  while line:
  
    line = string.strip(line)
#    sys.stderr.write('***%s\n' % (line))
    if issection_re.search(line)!=None:

      # Section found => new section in result dict

      # extract plain section name by searching [ aphanum-string ]
      # and stripping "[", "]" and white-spaces
      section_name = string.strip(section_name_re.search(line).group(0)[1:-1])
      # Create new sub-dict. If there are multiple sections (broken cnf-file)
      # with the same name, the last one is valid.
      keys[section_name]=[]
      result[section_name]={}

    elif isparamline_re.search(line)!=None:

      # Is valid parameter line

      # Extract parameter name
      name = paramline_numname_re.search(line).group(0)
      # Extract parameter num.name
      try:
        num,name = string.split(name,'.',1)
      except ValueError:
        num = ''
      
      # extract plain value part
      # and strip "=", "#" and white-spaces
      line = string.strip(line[string.index(line,'=')+1:])
      if line:
        valuepart = string.strip(paramline_valuepart_re.match(line).group(0))
        valuegroups = paramline_valuesplit_re.findall(valuepart)
      else:
        valuepart = ''
        valuegroups = []

#      sys.stderr.write('***valuegroups=%s\n' % (valuegroups))
      if len(valuegroups)>1:
        result[section_name][name] = []
	for valuetuple in valuegroups:
	  if isquoted_re.search(valuetuple[0]):
	    value = valuetuple[0][1:-1]
	  else:
	    value = valuetuple[0]
          # New entry in current section
          keys[section_name].append(name)
          # Store value of entry in dict
	  value = string.strip(value)
	  if value:
            result[section_name][name].append(value)
      elif len(valuegroups)==1:
        valuetuple = valuegroups[0]
	if isquoted_re.search(valuetuple[0]):
	  value = valuetuple[0][1:-1]
	else:
	  value = valuetuple[0]
        # New entry in current section
        keys[section_name].append(name)
        # Store value of entry in dict
        result[section_name][name] = string.strip(value)

    # Read next line from file
    line = cnf_file.readline()
    linenum = linenum+1

  cnf_file.close()

  return keys,result

########################################################################
# Objektklasse fuer eine CA-Definition
########################################################################

class caDataClass:

  def __init__(self):
    pass

  # returns 1 if the certificates of CA ca_name are
  # client certificates (depending on keyUsage and nsCertType).
  def isclientcert(self):
    if self.basicConstraints and self.basicConstraints=='CA:true':
      return 0
    if self.nsCertType:
      if type(self.nsCertType)==types.ListType:
	isClientCert=0
	for i in self.nsCertType:
          isClientCert = isClientCert or (i in ['email','client','objsign'])
      else:
	isClientCert = self.nsCertType in ['email','client','objsign']
      return isClientCert
    else:
      return 1
    
  # returns 1 if the certificates of CA ca_name are usable for
  # email (depending on keyUsage and nsCertType).
  def isemailcert(self):
    if self.basicConstraints and self.basicConstraints=='CA:true':
      return 0
    return (type(self.nsCertType)==types.ListType and ('email' in self.nsCertType)) or \
           (self.nsCertType=='email') or \
	   (self.nsCertType=='')

  # returns 1 if the certificates of CA ca_name are usable for
  # email (depending on keyUsage and nsCertType).
  def isservercert(self):
    if self.basicConstraints and self.basicConstraints=='CA:true':
      return 0
    return (type(self.nsCertType)==types.ListType and ('server' in self.nsCertType)) or \
           (self.nsCertType=='server') or \
	   (self.nsCertType=='')

########################################################################
# Objektklasse fuer eine Konfigurationsdatei
########################################################################

class OpenSSLConfigClass:

  def __init__(self,pathname):
    self.sectionkeys,self.data = GetAllSections(pathname)

  # FIX ME!!! Look for Netscape specs about key usage determination.

  # Build tree with CA hierarchy
  def getcatree(self):
    catree = {'.':[]}
    ca_names = self.sectionkeys.get('ca',[])
    for ca_name in ca_names:
      signedby = self.data[self.data['ca'][ca_name]].get('signedby','')
      if signedby:
        if catree.has_key(signedby):
	  catree[signedby].append(ca_name)
        else:
	  catree[signedby]=[ca_name]
      else:
	catree['.'].append(ca_name)
    return catree

  # Get all relevant data of a CA definition and its subsequent sections
  def getcadata(self,ca_name):
    ca = caDataClass()
    pyca_section = self.data.get('pyca',{})
    ca.sectionname = self.data['ca'][ca_name]
    ca_section = self.data[ca.sectionname]
    ca.name = ca_name
    ca.dir = ca_section.get('dir','')
    ca.serial = string.replace(ca_section.get('serial','$dir/serial'),'$dir',ca.dir)
    ca.certificate = string.replace(ca_section.get('certificate','$dir/cacert.pem'),'$dir',ca.dir)
    ca.private_key = string.replace(ca_section.get('private_key','$dir/private/cakey.pem'),'$dir',ca.dir)
    ca.database = string.replace(ca_section.get('database','$dir/index.txt'),'$dir',ca.dir)
    ca.pend_reqs_dir = string.replace(ca_section.get('pend_reqs_dir','$dir/pendreqs'),'$dir',ca.dir)
    ca.crl = string.replace(ca_section.get('crl','$dir/crl.pem'),'$dir',ca.dir)
    ca.crl_dir = string.replace(ca_section.get('crl_dir','$dir/crl'),'$dir',ca.dir)
    ca.new_reqs_dir = string.replace(ca_section.get('new_reqs_dir','$dir/newreqs'),'$dir',ca.dir)
    ca.old_reqs_dir = string.replace(ca_section.get('old_reqs_dir','$dir/oldreqs'),'$dir',ca.dir)
    ca.new_certs_dir = string.replace(ca_section.get('new_certs_dir','$dir/newcerts'),'$dir',ca.dir)
    ca.certs = string.replace(ca_section.get('certs','$dir/certs'),'$dir',ca.dir)
    ca.req = ca_section.get('req','req')
    ca.policy = ca_section.get('policy','')
    ca.signedby = ca_section.get('signedby','')
    ca.ca_reqfile = ca_section.get('ca_reqfile','')
    ca.ca_x509_extfile = ca_section.get('ca_x509_extfile','')
    ca.min_key_size = string.atoi(ca_section.get('min_key_size','0'))
    ca.default_days = string.atoi(ca_section.get('default_days','0'))
    ca.crl_days = string.atoi(ca_section.get('crl_days','0'))
    ca.crl_treshold = string.atoi(ca_section.get('crl_treshold','0'))

    ca.x509_extensions = ca_section.get('x509_extensions','')
    x509_extensions_section = self.data.get(ca.x509_extensions,{})

    # PKIX attributes
    ca.basicConstraints = x509_extensions_section.get('basicConstraints','')
    ca.keyUsage = x509_extensions_section.get('keyUsage','')
    ca.extendedKeyUsage = x509_extensions_section.get('extendedKeyUsage','')

    # Netscape attributes
    ca.nsCertType = x509_extensions_section.get('nsCertType','')
    ca.nsBaseUrl = x509_extensions_section.get('nsBaseUrl',pyca_section.get('nsBaseUrl',''))
    ca.nsCaRevocationUrl = x509_extensions_section.get('nsCaRevocationUrl','')
    ca.nsRevocationUrl = x509_extensions_section.get('nsRevocationUrl','')
    ca.nsCaPolicyUrl = x509_extensions_section.get('nsCaPolicyUrl','')
    ca.nsComment = x509_extensions_section.get('nsComment','')
    if type(ca.nsCertType)==types.ListType:
      ca.nsCertTypeStr=string.join(ca.nsCertType,'/')
    else:
      ca.nsCertTypeStr=ca.nsCertType

    return ca

  # get list of pathnames of all intermediate CA certficates
  # excluding the self-signed root CA cert
  def getcacertchain(self,ca_name):
    ca_section = self.data[self.data['ca'][ca_name]]
    result = []
    while ca_section.has_key('signedby'):
      ca_dir = ca_section.get('dir','')
      ca_certificate = string.replace(ca_section.get('certificate','$dir/cacert.pem'),'$dir',ca_dir)
      result.append(ca_certificate)
      ca_signedby = ca_section['signedby']
      if not self.data['ca'].has_key(ca_signedby):
        raise KeyError,'CA name not found'
      ca_section = self.data[self.data['ca'][ca_signedby]]
    return result
