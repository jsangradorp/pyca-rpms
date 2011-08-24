"""
ldif.py - Various routines for handling LDIF data

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

__version__ = '0.2.5'

import sys,string,binascii,re

try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO

attr_pattern = r'[\w;.]+(;[\w_-]+)*'
data_pattern = '([^,]+|".*?")'
rdn_pattern = attr_pattern + r'[\s]*=[\s]*' + data_pattern
dn_pattern   = rdn_pattern + r'([\s]*,[\s]*' + rdn_pattern + r')*'

#rdn_regex   = re.compile('^%s$' % rdn_pattern)
dn_regex   = re.compile('^%s$' % dn_pattern)

ldif_pattern = '^((dn(:|::) %(dn_pattern)s)|(%(attr_pattern)s(:|::) %(data_pattern)s)$)+' % vars()

ldif_regex   = re.compile('^%s$' % ldif_pattern,re.M)

def is_dn(s):
  """
  returns 1 if s is a LDAP DN
  """
  rm = dn_regex.match(s)
  return rm!=None and rm.group(0)==s

def is_ascii(s):
  """
  returns 1 if s is plain ASCII
  """
  if s:
    pos=0 ; s_len = len(s)
    while ((ord(s[pos]) & 0x80) == 0) and (pos<s_len-1):
      pos=pos+1
    if pos<s_len-1:
      return 0
    else:
      return (ord(s[pos]) & 0x80) == 0
  else:
    return 1

def BinaryAttribute(attr,buf,col=77):
  """
  Convert buf to a binary attribute representation
  """
  b64buf = '%s:: ' % (attr)
  buflen = len(buf)
  pos=0
  while pos<buflen:
    b64buf = '%s%s' % (b64buf,binascii.b2a_base64(buf[pos:min(buflen,pos+57)])[:-1])
    pos = pos+57

  b64buflen = len(b64buf)
  pos=col
  result = b64buf[0:min(b64buflen,col)]
  while pos<b64buflen:
    result = '%s\n %s' % (result,b64buf[pos:min(b64buflen,pos+col-1)])
    pos = pos+col-1
  return '%s\n' % result


def CreateLDIF(
  dn,			# string-represantation of distinguished name
  entry={},		# dictionary holding the LDAP entry {attr:data}
  binary_attrs=[]
):
  """
  Create LDIF formatted entry.
  
  The trailing empty line is NOT added.
  """
  # Write line dn: first
  if is_ascii(dn):
    result = ['dn: %s\n' % (dn)]
  else:
    result = [BinaryAttribute('dn',dn)]

  objectclasses = entry.get('objectclass',entry.get('objectClass',[]))
  for oc in objectclasses:
    result.append('objectclass: %s\n' % oc)
  attrs = entry.keys()[:]
  try:
    attrs.remove('objectclass')
    attrs.remove('objectClass')
  except ValueError:
    pass
  attrs.sort()
  for attr in attrs:
    if attr in binary_attrs:
      for data in entry[attr]:
        result.append(BinaryAttribute(attr,data))
    else:
      for data in entry[attr]:
        if is_ascii(data):
  	  result.append('%s: %s\n' % (attr,data))
	else:
          result.append(BinaryAttribute(attr,data))
  return string.join(result,'')


def ParseLDIF(
  f=StringIO(),		# file-object for reading LDIF input
  ignore_attrs=[],	# list of attribute types to ignore
  maxentries=0		# (if non-zero) specifies the maximum number of
  			# entries to be read from f
):
  """
  Parse LDIF data read from file object f
  """
  
  result = []

  # lower-case all
  ignored_attrs = map(string.lower,ignore_attrs)

  # Read very first line
  s = f.readline()

  entries_read = 0

  while s and (not maxentries or entries_read<maxentries):

    # Reading new entry

    # Reset entry data
    dn = ''; entry = {}; attr = ''; data = ''

    s = string.rstrip(s)

    while s:
    
      # Reading new attribute line
      attr,data=string.split(s,':',1)
      if data[0]==':':
        # Read attr:: data line => binary data assumed
        data = data[1:]
        binary = 1
      else:
        # Read attr: data line
        binary = 0

      s = f.readline()
      s = string.rstrip(s)

      # Reading continued multi-line data
      while s and s[0]==' ':
        data = data + string.strip(s)
        # Read next line
        s = f.readline()
        s = string.rstrip(s)

      attr = string.lower(string.strip(attr))

      if not attr in ignored_attrs:

	if binary:
          # binary data has to be BASE64 decoded
          data = binascii.a2b_base64(data)
	else:
          data = string.strip(data)

        # Add attr: data to entry
	if attr=='dn':
          dn = string.strip(data) ; attr = '' ; data = ''
          if not is_dn(dn):
	    raise ValueError, 'No valid string-representation of distinguished name.'
	else:
          if entry.has_key(attr):
            entry[attr].append(data)
          else:
            entry[attr]=[data]

    # end of entry reached marked by newline character(s)

    if entry:
      # append entry to result list
      result.append((dn,entry))
      entries_read = entries_read+1

    # Start reading next entry
    s = f.readline()

  return result
