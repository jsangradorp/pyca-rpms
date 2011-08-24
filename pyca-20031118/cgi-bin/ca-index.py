#!/usr/bin/python

"""
ca-index.py
(c) by Michael Stroeder <michael@stroeder.com>

This CGI-BIN program shows a pretty index of the CA definitions in
OpenSSL's config file (e.g. named openssl.cnf)
"""

__version__ = '0.6.6'

import os, sys, types, string, pycacnf, openssl, htmlbase

from pycacnf import opensslcnf, pyca_section

nsGetCertUrl = pyca_section.get('nsGetCertUrl','')
nsViewCertUrl = pyca_section.get('nsViewCertUrl','')
nsEnrollUrl  = pyca_section.get('nsEnrollUrl','')

ca_names = opensslcnf.sectionkeys.get('ca',[])

if not ca_names:
  htmlbase.PrintErrorMsg('No certificate authorities found.')
  sys.exit(0)

htmlbase.PrintHeader('Overview of certificate authorities')
htmlbase.PrintHeading('Overview of certificate authorities')
print """<TABLE BORDER WIDTH=100%>
<TR>
  <TH>CA name</TH>
  <TH COLSPAN=2>CA certificate</TH>
  <TH COLSPAN=2>CRL</TH>
  <TH>certificate<BR>types</TH>
  <TH>Comment</TH>
  <TH>View policy</TH>
</TR>
"""

for ca_name in ca_names:
  ca = opensslcnf.getcadata(ca_name)
  if nsEnrollUrl and ca.isclientcert():
    nsCertTypeStr = '<A HREF="%s%s/%s">%s</A>' % (ca.nsBaseUrl,nsEnrollUrl,ca_name,ca.nsCertTypeStr)
  else:
    if ca.nsCertTypeStr:
      nsCertTypeStr = '%s' % (ca.nsCertTypeStr)
    else:
      nsCertTypeStr = '&nbsp;'
  if ca.nsCaRevocationUrl:
    nsCaRevocationUrl='<A HREF="%s%s">load</A>' % (ca.nsBaseUrl,ca.nsCaRevocationUrl)
    nsViewRevocationUrl='<A HREF="%s%s/%s/crl">view</A>' % (ca.nsBaseUrl,nsViewCertUrl,ca_name)
  else:
    nsCaRevocationUrl   = '&nbsp;'
    nsViewRevocationUrl = '&nbsp;'
  if ca.nsCaPolicyUrl:
    nsCaPolicyUrl='<A HREF="%s%s">Policy of %s</A>' % (ca.nsBaseUrl,ca.nsCaPolicyUrl,ca_name)
  else:
    nsCaPolicyUrl='-'

  print """
<TR>
  <TD>%s</TD>
  <TD><A HREF="%s%s/%s/ca.crt">load</A></TD>
  <TD><A HREF="%s%s/%s/ca">view</A></TD>
  <TD>%s</TD>
  <TD>%s</TD>
  <TD>%s</TD>
  <TD>%s</TD>
  <TD>%s</TD>
<TR>
""" % (
  ca_name,
  ca.nsBaseUrl,
  nsGetCertUrl,
  ca_name,
  ca.nsBaseUrl,
  nsViewCertUrl,
  ca_name,
  nsCaRevocationUrl,
  nsViewRevocationUrl,
  nsCertTypeStr,
  ca.nsComment,
  nsCaPolicyUrl
)

print '</TABLE><P>'

print '<A HREF="cert-query.py">Search for issued certificates.</A>'

htmlbase.PrintFooter()
sys.exit(0)
