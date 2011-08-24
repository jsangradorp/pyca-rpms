##############################################################################
# ldapbase.py Version 0.1.2
# (c) by Michael Stroeder, michael.stroeder@propack-data.de
##############################################################################

import sys, string, re

dn_pattern   = r'([\w;.]+[\s]*=[^,]+)(,[ ]*[\w;.]+[\s]*=[^,]+)*'
dn_regex   = re.compile(dn_pattern)

# returns 1 if s is a LDAP DN
def is_dn(s):
  rm = dn_regex.match(s)
  return rm!=None and rm.group(0)==s

def normalize_dn(dn):
  result = string.split(dn,',')
  result = map(string.strip,result)
  return string.join(result,',')

# returns parent-DN of dn
def ParentDN(dn):
  return string.join(string.split(dn,',')[1:],',')

# returns a list of parent-DNs of dn
def ParentDNList(dn):
  result = []
  DNComponentList = string.split(dn,',')
  for i in range(1,len(DNComponentList)):
    result.append(string.join(DNComponentList[i:],','))
  return result

# parse a LDAP URL and return (host,dn,attributes,scope,filter)
# host         LDAP host
# dn           distinguished name
# attributes   list with attributes
# scope        search scope string
# filter       LDAP search filter
def parse_ldap_url(ldap_url):
  dummy,rest = string.split(ldap_url,'://',1)
  try:
    host,rest = string.split(rest,'/',1)
  except ValueError:
    host='' ; dn=rest
  paramlist=string.split(rest,'?')
  dn          = paramlist[0]
  try:
    attributes  = string.split(paramlist[1],',')
  except IndexError:
    attributes  = []
  try:
    scope       = paramlist[2]
  except IndexError:
    scope       = ''
  try:
    filter      = paramlist[3]
  except IndexError:
    filter      = ''
  return (host,dn,attributes,scope,filter)


class Attribute:

  def __init__(self):
    self.name=''

  def put(self,name,oid='',syntax='',alias=[],notes=''):
    self.name=name
    self.oid=oid
    self.alias=alias
    self.notes=notes

  def parse(self,attr_schemastr):
    pass


class ObjectClass:

  def __init__(self):
    self.name=''

  def put(self,name,oid='',syntax='',sup='',must=[],may=[],notes=''):
    self.name=name
    self.oid=oid
    self.abstract=abstract
    self.sup=sup
    self.must=must
    self.may=may
    self.syntax=syntax
    self.notes=notes

  def parse(self,oc_schemastr):
    pass


class Schema:

  def __init__(self,host):
    self.host=host
    self.oc_def = {}
    self.oc_list = []
    self.attr_def = {}
    self.attr_list = []

  def AddObjectClass(self,name,oid='',sup='',must=['objectClass'],may=[],syntax='',notes=''):
    if not name in self.oc_list:
      self.oc_list.append(name)
      self.oc_def['name']=ObjectClass()
    self.oc_def['name'].put(name,oid,sup,must,may,syntax,notes)

  def AddAttribute(self,name,oid='',syntax='',alias=[],notes=''):
    if not name in self.attr_list:
      self.attr_list.append(name)
      self.attr_def['name']=Attribute()
    self.attr_def['name'].put(name,oid,syntax,alias,notes)

  def v3SchemaQuery(self,ldapconn,basedn='cn=schema',searchfilter='objectclass=subschema'):
    schema = ldapconn.search_s()

  def ReadOpenLDAPConf(self,slapdconf):
    f = open(slapdconf,'r')

