########################################################################
# certhelper.py
# (c) by Michael Stroeder, michael@stroeder.com
########################################################################
# Deal with X.509 certificates and cert requests with
# plain Python 1.5.2 lib
########################################################################

import string, re, base64, md5, sha

pem_re = re.compile('-----BEGIN (CERTIFICATE|X509 CRL|CERTIFICATE REQUEST)-----([ \w+/=\r\n]+?)-----END (CERTIFICATE|X509 CRL|CERTIFICATE REQUEST)-----',re.S+re.M)

def MD5Fingerprint(cert_der='',delimiter=':'):
  """
  MD5 fingerprint in dotted notation (delimiter between bytes)
  """
  cert_md5 = md5.new(cert_der).digest()
  cert_fingerprint = []
  for i in cert_md5:
    cert_fingerprint.append(string.upper('%02x' % (ord(i))))
  return string.join(cert_fingerprint,delimiter)

def SHA1Fingerprint(cert_der='',delimiter=':'):
  """
  Return SHA-1 fingerprint in dotted notation (delimiter between bytes)
  """
  cert_sha1 = sha.new(cert_der).digest()
  cert_fingerprint = []
  for i in cert_sha1:
    cert_fingerprint.append(string.upper('%02x' % (ord(i))))
  return string.join(cert_fingerprint,delimiter)

def extract_pem(cert_text):
  """
  Extract all base64 encoded certs in a text file to a list of strings
  """
  result = []
  for begin_type,cert_base64,end_type in pem_re.findall(cert_text):
    if begin_type!=end_type:
      raise ValueError,"-----BEGIN %s----- and -----END %s----- does not match" % (begin_type,end_type)
    result.append((begin_type,string.strip(cert_base64)))
  return result

def der2pem(cert_der,cert_type='CERTIFICATE'):
  """
  Convert single binary DER-encoded certificate to base64 encoded format
  """
  return """-----BEGIN %s-----
%s-----END %s-----
""" % (cert_type,base64.encodestring(cert_der),cert_type)

def pem2der(cert_text):
  """
  Convert single base64 encoded certificate to binary DER-encoded format
  """
  cert_type,cert_base64  = extract_pem(cert_text)[0]
  return base64.decodestring(string.strip(cert_base64))

