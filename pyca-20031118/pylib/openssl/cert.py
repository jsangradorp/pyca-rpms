#######################################################################
# openssl.cert.py Version 0.6.6
# (c) by Michael Stroeder, michael.stroeder@propack-data.de
########################################################################
# Module for accessing certificate files
########################################################################

import sys, string, os, time

import openssl, charset, certhelper

certformats = ['pem','der','txt','net']
X509v1_certattrlist = ['CN','Email','OU','O','L','ST','C']


########################################################################
# functions used throughout this module
########################################################################


def GuessFormatbyExt(certfilename):
  ext = string.lower(os.path.splitext(certfilename)[1])
  if ext in certformats:
    return ext
  else:
    return 'pem'


def GetCertValues(certfilename,inform='',command='x509'):

  command = string.lower(command)
  if command == 'x509':
    opensslcommand = '%s x509 -in %s -fingerprint -inform %s -noout -subject -issuer -dates -serial -hash' % (openssl.bin_filename,certfilename,inform)
  elif command == 'crl':
    opensslcommand = '%s crl -in %s -inform %s -noout -issuer -lastupdate -nextupdate -hash' % (openssl.bin_filename,certfilename,inform)

  result={}
  hash=''
  pipe = os.popen(opensslcommand)
  s=pipe.readline()
  while s:
    try:
      name, value = string.split(s,'=',1)
    except ValueError:
      hash = string.strip(s)
    result[name]=string.strip(value)
    s=pipe.readline()
  rc = pipe.close()
  if rc and rc!=256:
    raise IOError,"Error %s: %s" % (rc,opensslcommand)

  return hash, result


########################################################################
# X509CertificateClass
########################################################################

class X509CertificateClass:

  def __init__(self,certfilename,inform=''):

    self.filename = certfilename
    if not inform:
      self.format = GuessFormatbyExt(self.filename)
    else:
      self.format = inform
    self.hash,certattrs = GetCertValues(self.filename,self.format,'x509')
    self.issuer = openssl.db.SplitDN(certattrs.get('issuer',{}))
    self.subject = openssl.db.SplitDN(certattrs.get('subject',{}))
    self.serial  = string.atoi(certattrs.get('serial','-1'),16)
    self.notBefore = certattrs.get('notBefore','')
    if self.notBefore:
      self.notBefore_secs = time.mktime(time.strptime(self.notBefore,'%b %d %H:%M:%S %Y GMT'))
    else:
      self.notBefore_secs = 0
    self.notAfter = certattrs.get('notAfter','')
    if self.notAfter:
      self.notAfter_secs = time.mktime(time.strptime(self.notAfter,'%b %d %H:%M:%S %Y GMT'))
    else:
      self.notAfter_secs = 0
    # Fingerprint suchen
    certattrs_keys = certattrs.keys()
    self.fingerprint = {}
    for i in certattrs_keys:
      if i[-11:]=='Fingerprint':
        self.fingerprint[string.upper(string.split(i)[0])] = string.split(certattrs[i],':')

  # get serial number of certificate
  def serial(self):
    return string.atoi(self.serial)

  def getfingerprint(self,digest='md5',delimiter=':'):
    digest = string.upper(digest)
    if not digest in ['MD2','MD5','MDC2','RMD160','SHA','SHA1']:
      raise ValueError, 'Illegal parameter for digest: %s' % digest
    elif self.fingerprint.has_key(digest):
      result = self.fingerprint[digest]
    elif digest=='MD5':
      return certhelper.MD5Fingerprint(certhelper.pem2der(open(self.filename,'r').read()),delimiter)
    elif digest=='SHA1':
      return certhelper.SHA1Fingerprint(certhelper.pem2der(open(self.filename,'r').read()),delimiter)
    else:
      opensslcommand = '%s x509 -in %s -inform %s -outform DER | %s %s' % (
        openssl.bin_filename,
        self.filename,
        self.format,
        openssl.bin_filename,
        string.lower(digest)
      )
      f = os.popen(opensslcommand)
      rawdigest = string.strip(f.read())
      rc = f.close()
      if rc and rc!=256:
	raise IOError,"Error %s: %s" % (rc,opensslcommand)
      result = []
      for i in range(len(rawdigest)/2):
        result.append(rawdigest[2*i:2*(i+1)])
      self.fingerprint[digest] = result
    return string.upper(string.join(result,delimiter))

  # return certificate in a string, desired format given in outform
  def readcertfile(self,outform='PEM'):
    if not (string.lower(outform) in certformats):
      raise ValueError,'invalid certificate output format'
    f = os.popen('%s x509 -in %s -inform %s -outform %s' % (openssl.bin_filename,self.filename,self.format,outform))
    buf = f.read()
    result = []
    while buf:
      result.append(buf)
      buf = f.read()
    rc = f.close()
    if rc and rc!=256:
      raise IOError,"Error %s: %s" % (rc,opensslcommand)
    return string.join(result)

  # Return a string containing the cert attributes
  def asciiprint(self):

    # Convert character sets
    subjectdatalist = []
    issuerdatalist = []
    for attr in X509v1_certattrlist:
      subjectdatalist.append('%-5s: %s' % (attr,string.strip(charset.asn12iso(self.subject.get(attr,'')))))
      issuerdatalist.append('%-5s: %s' % (attr,string.strip(charset.asn12iso(self.issuer.get(attr,'')))))

    return """This certificate belongs to:
%s

This certificate was issued by:
%s

Serial Number: %s

This certificate is valid
from %s until %s.

Certificate Fingerprint:
SHA-1: %s
MD5  : %s
""" % ( \
        string.join(subjectdatalist,'\n'),
        string.join(issuerdatalist,'\n'),
        self.serial,
	self.notBefore,
	self.notAfter,
	self.getfingerprint('sha1'),
	self.getfingerprint('md5'),
       )

  # Return a string containing a nice formatted <TABLE> with cert info
  def htmlprint(self):

    # Convert character sets
    subjectdatalist = []
    issuerdatalist = []
    for attr in X509v1_certattrlist:
      subjectdatalist.append(string.strip(charset.asn12html4(self.subject.get(attr,''))))
      issuerdatalist.append(string.strip(charset.asn12html4(self.issuer.get(attr,''))))

    return """
  <TABLE BORDER=1 WIDTH="100%%" CELLPADDING="5%%">
  <TR>
    <TD WIDTH="50%%">
      <DL>
        <DT><STRONG>This certificate belongs to:</STRONG></DT>
        <DD>%s</DD>
      </DL>
    </TD>
    <TD>
      <DL>
        <DT><STRONG>This certificate was issued by:</STRONG></DT>
        <DD>%s</DD>
      </DL>
    </TD>
  </TR>
  <TR>
    <TD COLSPAN=2>
      <DL>
        <DT><STRONG>Serial Number:</STRONG><DT>
        <DD>%s</DD>
        <DT><STRONG>This certificate is valid from %s until %s.</STRONG></DT>
        <DT><STRONG>Certificate Fingerprint:</STRONG></DT>
        <DD><PRE>SHA-1: %s<BR>MD5:   %s</PRE></DD>
      </DL>
    </TD>
  </TR>
  </TABLE>
  """ % ( \
          string.join(subjectdatalist,'<BR>'),
          string.join(issuerdatalist,'<BR>'),
          self.serial,
	  self.notBefore,
	  self.notAfter,
	  self.getfingerprint('sha1'),
	  self.getfingerprint('md5'),
         )


########################################################################
# CRLClass
########################################################################

class CRLClass:

  def __init__(self,crlfilename,inform=''):
    self.filename = crlfilename
    if not inform:
      self.format = GuessFormatbyExt(self.filename)
    else:
      self.format = inform
    self.hash,certattrs = GetCertValues(self.filename,self.format,'crl')
    self.issuer = openssl.db.SplitDN(certattrs.get('issuer',openssl.db.empty_DN_dict))
    self.hash  = certattrs.get('hash','')
    self.lastUpdate = certattrs.get('lastUpdate','')
    if self.lastUpdate:
      self.lastUpdate_secs = time.mktime(time.strptime(self.lastUpdate,'%b %d %H:%M:%S %Y GMT'))
    else:
      self.lastUpdate_secs = 0
    self.nextUpdate = certattrs.get('nextUpdate','')
    if self.nextUpdate:
      self.nextUpdate_secs = time.mktime(time.strptime(self.nextUpdate,'%b %d %H:%M:%S %Y GMT'))
    else:
      self.notAfter_secs = 0

  # return certificate in a string, desired format given in outform
  def readcertfile(self,outform='PEM'):
    if not (string.lower(outform) in certformats):
      raise ValueError,'invalid certificate output format'
    f = os.popen('%s crl -in %s -inform %s -outform %s' % (openssl.bin_filename,self.filename,self.format,outform))
    buf = f.read()
    result = []
    while buf:
      result.append(buf)
      buf = f.read()
    rc = f.close()
    if rc and rc!=256:
      raise IOError,"Error %s: %s" % (rc,opensslcommand)
    return string.join(result)


########################################################################
# SPKACClass
########################################################################

class SPKACClass:

  def __init__(self,spkacfilename,inform=''):
    self.filename = spkacfilename
    self.data = {}
    spkacfile = open(self.filename,'r')
    s = spkacfile.readline()
    while s:
      try:
        attr,value=string.split(s,'=',1)
        self.data[string.strip(attr)]=string.strip(value)
      except ValueError:
        pass
      s = spkacfile.readline()

