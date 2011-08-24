"""
charset.py - Module for converting characters sets
(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

__version__ = '0.4.1'

import sys, string

# Alphabet for encrypted passwords (see module crypt)
crypt_alphabet = './0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
crypt_alphabet_len = len(crypt_alphabet)


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


def escapeHTML(s,escape_html_chars='&;<>":={}()'):
  """
  Escape all characters with a special meaning in HTML
  to appropriate character tags
  """
  result = ''; escape_html_chars_list = list(escape_html_chars)
  for c in s:
    if c in escape_html_chars:
      result=result+'&#%d;'%ord(c)
    else:
      result=result+c
  return result


def iso2utf(s):
  """
  Convert ISO-8859-1 to UTF-8 encoded Unicode
  """
  new = ''
  for ch in s:
    c=ord(ch)
    if (c & 0x80) == 0:
      new = new+ch
    else:
      new = new+chr(0xC0 | (0x03 & (c >> 6)))+chr(0x80 | (0x3F & c))
  return new


UTF8len= ( 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	   2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5, 6 )

UTF8mask = (0x3F,0x7F,0x1F,0x0F,0x07,0x03,0x01)

def utf2iso(s):
  """
  Convert UTF-8 encoded Unicode to ISO-8859-1
  """
  new = ''
  ind = 0
  slen = len(s)
  while ind < slen:
    c=ord(s[ind])
    ind = ind+1
    clen = UTF8len[(c >> 2) & 0x3F]
    u = c & UTF8mask[clen]
    if clen==0:
      clen = 4
    else:
      clen = clen-1
    while clen and ind < slen:
      c=ord(s[ind])
      ind = ind+1
      if (c & 0xC0) == 0x80:
        u = (u << 6) | (c & 0x3F)
      else:
        ind = ind-1
        break
      clen = clen-1
    if (u <= 0xFF):
      new = new+chr(u)
    else:
      new = new+'?'
  return new


def utf2html4(s):
  """
  Convert UTF-8 encoded Unicode to HTML-4 character representation
  """
  new = ''
  ind = 0
  slen = len(s)
  while ind < slen:
    c=ord(s[ind])
    ind = ind+1
    clen = UTF8len[(c >> 2) & 0x3F]
    u = c & UTF8mask[clen]
    if clen==0:
      clen = 4
    else:
      clen = clen-1
    while clen and ind < slen:
      c=ord(s[ind])
      ind = ind+1
      if (c & 0xC0) == 0x80:
        u = (u << 6) | (c & 0x3F)
      else:
        ind = ind-1
        break
      clen = clen-1
    if u<128:
      new = new + chr(u)
    else:
      new = new + '&#%d;' % u
  return new


def iso2html4(s):
  """
  Convert ISO-8859-1 to HTML-4 character representation
  """
  new = ''
  for ch in s:
    c=ord(ch)
    if (c & 0x80)==0:
      new = new + ch
    else:
      new = new + '&#%d;' % (c)
  return new


def iso2t61(s):
  """
  Convert ISO-8859-1 to T.61 character representation
  """
  new = ''
  for ch in s:
    c=ord(ch)
    if (c & 0x80) == 0:
      new = new+ch
    else:
      new = '%s\\x%X' % (new,ord(ch))
  return new


def t612iso(s):
  """
  Convert T.61 character representation to ISO-8859-1
  """
  new = ''
  slashpos = string.find(s,'\\x')
  while slashpos!=-1:
    if (s[slashpos]==0) or (s[slashpos]>0 and s[slashpos-1]!='\\'):
      new = new+s[0:slashpos]+chr(string.atoi(s[slashpos+2:slashpos+4],16))
      s = s[slashpos+4:]
    else:
      new = new+s[0:slashpos-1]
      s = s[slashpos+1:]
    slashpos = string.find(s,'\\x')
  return new+s


def t612html4(s):
  """
  Convert T.61 character representation to HTML-4 character representation
  """
  new = ''
  slashpos = string.find(s,'\\x')
  while slashpos!=-1:
    if (s[slashpos]==0) or (s[slashpos]>0 and s[slashpos-1]!='\\'):
      new = new+s[0:slashpos]+'&#%d;' % string.atoi(s[slashpos+2:slashpos+4],16)
      s = s[slashpos+4:]
    else:
      new = new+s[0:slashpos-1]
      s = s[slashpos+1:]
    slashpos = string.find(s,'\\x')
  return new+s


def iso2asn1(s):
  """
  Convert ISO-8859-1 to BMPString
  """
  new = ''
  for ch in s:
    c=ord(ch)
    if (c & 0x80) == 0:
      new = '%s\\x00%s' % (new,ch)
    else:
      new = '%s\\x00\\x%X%s' % (new,ord(ch),ch)
  return new


def asn12iso(s):
  """
  Convert BMPString to ISO-8859-1
  """
  return t612iso(string.replace(s,'\\x00',''))


def asn12html4(s):
  """
  Convert BMPString to HTML-4 character representation
  """
  return t612html4(string.replace(s,'\\x00',''))


recode_func = {
  'ISO-8859-1': {
      'UTF-8'      : iso2utf,
      'HTML4'      : iso2html4
    },
  'ISO-8859-15': {
      'UTF-8'      : iso2utf,
      'HTML4'      : iso2html4
    },
  'UTF-8': {
      'HTML4'      : utf2html4,
      'ISO-8859-1' : utf2iso
    }
  }

def recode(s,source,target):
  """
  Convert from/to known character set / encoding
  """
  if source==target:
    return s

  return recode_func[string.upper(source)][string.upper(target)](s)

