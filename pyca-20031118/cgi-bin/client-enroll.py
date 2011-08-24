#!/usr/bin/python

"""
client-enroll.py - certificate enrollment with mainstream web browsers
(c) by Michael Stroeder <michael@stroeder.com>
"""

Version='0.6.6'

########################################################################
# CGI-BIN for creating certificate requests
########################################################################

import os, sys, types, string, re, socket, \
       pycacnf, \
       cgiforms, cgihelper, charset, ipadr, htmlbase, certhelper

from pycacnf import opensslcnf, pyca_section
from charset import iso2utf, iso2html4
from cgihelper import BrowserType,known_browsers,known_browsers_rev

########################################################################
# "Internet"-Funktionen
########################################################################

# Aus einer Mailadresse die Domain herausloesen
# Ergebnis ist Teilstring hinter letztem(!) @
# falls kein @ vorhanden, dann Leerstring
def DomainAdr(MailAdr=""):
  splitted=string.split(MailAdr,'@')
  if len(splitted)>1:
    return splitted[-1]
  else:
    return ''

# String der Hilfe-URL zu bestimmtem Parameter zurueckgeben
def HelpURL(HelpUrl,name,text):
  return '<A HREF="%s.html#%s">%s</A>' % \
         (HelpUrl,name,iso2html4(text))

# Print list of possible cert types
def PrintCertTypes(ca_names):
  htmlbase.PrintHeader('Start enrollment for certificate request')
  htmlbase.PrintHeading('Start enrollment for certificate request')
  print """This certificate authority issues several types
of client certificates.<BR>Please choose the appropriate certificate
type below:<P>
<TABLE CELLSPACING=10%%>"""
  for ca_name in ca_names:
    ca = opensslcnf.getcadata(ca_name)
    if ca.isclientcert():
      if ca.nsCaPolicyUrl:
        nsCaPolicyUrlStr = '<A HREF="%s%s">(view policy)' % (ca.nsBaseUrl,ca.nsCaPolicyUrl)
      else:
        nsCaPolicyUrlStr = '&nbsp;'
      print '<TR><TD><A HREF="%s/%s">%s</A></TD><TD>%s</TD><TD>%s</TD></TR>' % (os.environ.get('SCRIPT_NAME','client-enroll.py'),ca_name,ca_name,ca.nsComment,nsCaPolicyUrlStr)
  print '</TABLE>'
  htmlbase.PrintFooter()

# Ausgabe eines leeren Eingabeformulars
def PrintEmptyForm(form,ca_name,scriptmethod='POST'):
  print '<FORM ACTION="%s/%s" METHOD="%s" ACCEPT-CHARSET="iso-8859-1">' % (os.environ.get('SCRIPT_NAME','client-enroll.py'),ca_name,scriptmethod)
  print '<TABLE WIDTH=100% BORDER>'
  for i in form.keys:
    for j in form.field[i]:
      print '<TR><TD>%s%s</TD><TD>%s</TD></TR>' % (HelpURL(HelpUrlBase,j.name,j.text),' <FONT SIZE="+2">*</FONT>'*j.required,j.inputfield())
  print '</TABLE>'
  print '<INPUT TYPE="submit" VALUE="Send">'
  print '<INPUT TYPE="reset" VALUE="Reset">'
  print '</FORM>'
  return

def PrintInput(form,cellpadding=5,width=100):
  print '<TABLE BORDER CELLPADDING=%d%% WIDTH=%d%%>' % (cellpadding,width)
  formKeys = form.inputkeys[:]
  try:
    formKeys.remove('challenge')
  except ValueError:
    pass

  for i in formKeys:
    for j in form.field[i]:
      print '<TR><TD WIDTH=35%%>%s</TD><TD>%s</TD></TR>' % \
             (HelpURL(HelpUrlBase,j.name,j.text),j.contentprint())
  print '</TABLE>'
  return

# Ausgabe eines Formulars zur Schuesselerzeugung
def PrintKeygenForm(form,ca_name,ca,browsertype,scriptmethod='POST'):

  print """Content-type: text/html\n
<HTML>
  <HEAD>
    <TITLE>Create key pair and certificate request</TITLE>
"""
  if browsertype=='MSIE':
    import vbs
    vbs.PrintVBSXenrollObject()
    print '<SCRIPT Language=VBSCRIPT>\n<!-- '
    vbs.PrintVBSCryptoProvider()
    vbs.PrintVBSKeyGenCode(form)
    print ' -->\n</SCRIPT>'
  print '</HEAD><BODY onLoad=KeySizeSelectList() %s>' % htmlbase.bodyPARAM
  htmlbase.PrintHeading('Create key pair and certificate request')
  print 'Your key pair and certificate request can be generated now.<BR>'
  print 'Please have a look below to check if your input data was correct.<P>'
  # Print input given by user as readable table and hidden input fields
  PrintInput(form)
  print '<FORM name="KeyGenForm" ACTION="%s/%s" METHOD=%s ACCEPT-CHARSET="iso-8859-1">' % (os.environ.get('SCRIPT_NAME','client-enroll.py'),ca_name,scriptmethod)
  for i in form.inputkeys:
    for j in form.field[i]:
      print '<INPUT TYPE="hidden" NAME="%s" VALUE="%s">' % (j.name,j.content)

  # Print hint about minimum key size
  if ca.min_key_size>0:
    print """Please note:<BR>
The certificate type <STRONG>%s</STRONG> requires a minimum key size of <STRONG>%d</STRONG> bits!
If you are not able to choose a key length equal or greater than <STRONG>%d</STRONG> the
certificate authority will refuse to issue a certificate for your certificate request!<P>
""" % (ca_name,ca.min_key_size,ca.min_key_size)

  if browsertype=='MSIE':
    print '<P>Key size: <SELECT NAME="KeySize"></SELECT></P><INPUT TYPE="hidden" NAME="PKCS10" VALUE="">'
    print '<INPUT TYPE="BUTTON" onClick="GenTheKeyPair()" VALUE="Generate key pair"></FORM>'
  else:
    print '<P>%s:%s</P><INPUT TYPE="submit" VALUE="Generate key pair"></FORM>' % ( \
      HelpURL(HelpUrlBase,form.field['SPKAC'][0].name,form.field['SPKAC'][0].text),\
      form.field['SPKAC'][0].inputfield(form.field['challenge'][0].content) \
    )
  htmlbase.PrintFooter()

########################################################################
# Main
########################################################################

# Read several parameters from config

MailRelay           = pyca_section.get('MailRelay','localhost')
TmpDir              = pyca_section.get('TmpDir','/tmp')

caCertReqMailAdr    = pyca_section.get('caCertReqMailAdr','')
caPendCertReqValid  = string.atoi(pyca_section.get('caPendCertReqValid','0'))

caInternalCertTypes = pyca_section.get('caInternalCertTypes',[])
if type(caInternalCertTypes)!=types.ListType:
  caInternalCertTypes = [caInternalCertTypes]

caInternalIPAdr     = pyca_section.get('caInternalIPAdr',['127.0.0.1/255.255.255.255'])
if type(caInternalIPAdr)!=types.ListType:
  caInternalIPAdr = [caInternalIPAdr]

caInternalDomains   = pyca_section.get('caInternalDomains','')
if type(caInternalDomains)!=types.ListType:
  caInternalDomains = [caInternalDomains]

ScriptMethod        = pyca_section.get('ScriptMethod','POST')

# Read wanted certificate type from PATH_INFO
ca_name = os.environ.get('PATH_INFO','')[1:]

# Get list of possible certificate type from config
ca_names = opensslcnf.sectionkeys.get('ca',[])

# Check for valid certificate type
if not ca_names:
  htmlbase.PrintErrorMsg('No certificate authorities found.')
  sys.exit(0)
if not ca_name:
  PrintCertTypes(ca_names)
  sys.exit(0)
if not ca_name in ca_names:
  # CA-Definition nicht in openssl-Konfiguration enthalten
  htmlbase.PrintErrorMsg('Unknown certificate authority "%s".' % ca_name)
  sys.exit(0)

# Check for "internal" IP address of client
if (ca_name in caInternalCertTypes) and \
   not ipadr.MatchIPAdrList(os.environ.get('REMOTE_ADDR',''),caInternalIPAdr):
  htmlbase.PrintErrorMsg('This type of certificate request is restricted to internal hosts!')
  sys.exit(0)

ca = opensslcnf.getcadata(ca_name)

HelpUrlBase = '%s%s%s' % ( \
		ca.nsBaseUrl, \
		pyca_section.get('HelpUrl',''), \
		os.path.splitext(os.path.basename(os.environ.get('SCRIPT_NAME','')))[0] \
	      )

policy_section = opensslcnf.data.get(ca.policy,{})
req_section = opensslcnf.data.get(ca.req,{})

if req_section and req_section.has_key('distinguished_name'):
  req_distinguished_name_section = opensslcnf.data.get(req_section['distinguished_name'],{})
  req_distinguished_name_keys = opensslcnf.sectionkeys.get(req_section['distinguished_name'],[])
else:
  htmlbase.PrintErrorMsg('Request section for "%s" not found.' % ca_name)
  sys.exit(0)

# Hier Verwendungszweck der Zertifikate pruefen
if not ca.isclientcert():
  htmlbase.PrintErrorMsg('Certificate authority "%s" does not issue client certificates.' % ca_name)
  sys.exit(0)

# form initialisieren
form = cgiforms.formClass(charset='iso-8859-1')

# Die gueltigen Inputattribute setzen
alphanumregex = r'[0-9a-zA-Z\344\366\374\304\326\334\337ß/\'"._ -]*'
# telephoneregex = r'^\+[0-9][0-9]-[0-9]*-[0-9]*'

# Check which browser is used
http_browsertype,http_browserversion = BrowserType(os.environ.get('HTTP_USER_AGENT',''))
key_gen_browsers = {'Microsoft Internet Explorer':('PKCS10','pem'),'Netscape Navigator':('SPKAC','spkac'),'Opera':('SPKAC','spkac')}
if not known_browsers.get(http_browsertype,http_browsertype) in key_gen_browsers.keys():
  http_browsertype=''

form.add(cgiforms.formSelectClass('browsertype','Browser Software',key_gen_browsers.keys(),known_browsers.get(http_browsertype,''),required=1))
form.add(cgiforms.formPasswordClass('challenge','Initial Master Secret',30,alphanumregex,required=1))

# The form is build by looking at a [req] section in openssl.cnf

dn_attr_keys = []
dn_attr = {}
for i in req_distinguished_name_keys:
  l = string.split(i,'_')
  attr_name = string.strip(l[0])
  if not attr_name in dn_attr_keys:
    dn_attr_keys.append(attr_name)
    dn_attr[attr_name]={'comment':'','max':'40','regex':alphanumregex,'default':''}
  if len(l)>1:
    dn_attr[attr_name][l[1]]=req_distinguished_name_section.get(i,'')
  elif len(l)==1:
    dn_attr[attr_name]['comment']=req_distinguished_name_section.get(i,attr_name)

for i in dn_attr_keys:
  imaxlength=string.atoi(dn_attr[i].get('max','40'))
  if imaxlength>40:
    isize=40
  else:
    isize=imaxlength
  policy_field = policy_section.get(i,'optional')
  if policy_field=='match':
    if type(dn_attr[i]['default'])==types.ListType:
      dn_attr[i]['default']=dn_attr[i]['default'][0]
    form.add(cgiforms.formHiddenInputClass(i,dn_attr[i]['comment'],imaxlength,dn_attr[i]['regex'],dn_attr[i]['default'],required=1,show=1))
  else:
    if type(dn_attr[i]['default'])==types.ListType:
      dn_attr[i]['default'].sort()
      form.add(cgiforms.formSelectClass(i,dn_attr[i]['comment'],dn_attr[i]['default'],required=policy_field=='supplied'))
    else:
      form.add(cgiforms.formInputClass(i,dn_attr[i]['comment'],imaxlength,dn_attr[i]['regex'],dn_attr[i]['default'],required=policy_field=='supplied',size=isize))

# Schon Parameter vorhanden?
if not form.contentlength:

  import time

  # Aufruf erfolgte ohne Parameter =>
  # 0. Schritt: leeres Eingabeformular ausgeben

  if not ca.nsComment:
    ca.nsComment = 'No comment'
  if ca.nsCaPolicyUrl:
    nsCommentStr = '<A HREF="%s%s">%s</A>' % (ca.nsBaseUrl,ca.nsCaPolicyUrl,ca.nsComment)
  else:
    nsCommentStr = ca.nsComment

  htmlbase.PrintHeader('Input form for certificate request')
  htmlbase.PrintHeading('Input form for certificate request')

  if not http_browsertype:
    print '<P><STRONG>Your browser type could not be automatically determined.<BR>Please choose the browser you are using.</STRONG></P>'

  print """<TABLE>
<TR><TD>Certificate authority:</TD><TD><STRONG>%s</STRONG></TD></TR>
<TR><TD>Certificate type:</TD><TD><STRONG>%s</STRONG></TD></TR>
<TR><TD>Certificate comment:</TD><TD><STRONG>%s</STRONG></TD></TR>
</TABLE>
<P>
  Certificates of this type will be valid for <STRONG>%d days</STRONG>, approximately until <STRONG>%s</STRONG>.
</P>
""" % (ca_name,
       ca.nsCertTypeStr,
       nsCommentStr,
       ca.default_days,
       time.strftime('%Y-%m-%d',time.gmtime(time.time()+86400*ca.default_days))
      )
  print """You can apply for a certificate by filling out the input form below.
Click on the names of the parameters to get further informations about the
usage and format restrictions of the input data.<P>
Required input parameters are marked with *.
"""
  PrintEmptyForm(form,ca_name)
  htmlbase.PrintFooter()
  sys.exit(0)

# 1. und 2. Schritt haben Schluesselfeld
form.add(cgiforms.formInputClass('KeySize','Key Size',100,alphanumregex))
form.add(
  cgiforms.formInputClass(
    'PKCS10',
    'PKCS#10 Request',
    2000,
    (
      r'[ \w+/=\r\n]+',
      re.S+re.M)
  )
)
form.add(cgiforms.formKeygenClass('SPKAC','Public Key and Challenge',6000))

# Aufruf erfolgte mit Parametern
try:
  form.getparams(ignoreemptyparams=1)
except cgiforms.formContentLengthException,e:
  htmlbase.PrintErrorMsg('Content length invalid.')
  sys.exit(0)
except cgiforms.formParamNameException,e:
  htmlbase.PrintErrorMsg('Unknown parameter "%s".' % (e.name))
  sys.exit(0)
except cgiforms.formParamsMissing,e:
  htmlbase.PrintHeader('Error')
  htmlbase.PrintHeading('Error')
  print """The following parameter(s) is/are missing:<P>
<UL>
  <LI>%s
</UL><P>
Required input parameters are marked with *.
""" % (string.join(map(lambda x: x[1],e.missing),'<LI>'))
  for k in ['PKCS10','KeySize','SPKAC']:
    try:
      form.keys.remove(k)
    except ValueError:
      pass
  for i in form.inputkeys:
    form.field[i][0].default=form.field[i][0].content
  PrintEmptyForm(form,ca_name)
  htmlbase.PrintFooter()
  sys.exit(0)
except cgiforms.formParamContentException,e:
  htmlbase.PrintHeader('Error')
  htmlbase.PrintHeading('Error')
  print 'Content of field "%s" has invalid format.<P>' % (e.text)
  form.keys.remove(RequestDataKey)
  for i in form.inputkeys:
    form.field[i][0].default=form.field[i][0].content
  PrintEmptyForm(form,ca_name)
  htmlbase.PrintFooter()
  sys.exit(0)
except cgiforms.formParamStructException,e:
  htmlbase.PrintErrorMsg('Too many (%d) parameters for field "%s".' % (e.count,e.name))
  sys.exit(0)
except cgiforms.formParamLengthException,e:
  htmlbase.PrintErrorMsg('Content too long. Field "%s" has %d characters.' % (e.text,e.length))
  sys.exit(0)

if 'browsertype' in form.inputkeys and \
  form.field['browsertype'][0].content in key_gen_browsers.keys():
  browsertype = known_browsers_rev[form.field['browsertype'][0].content]
else:
  browsertype = http_browsertype

RequestDataKey,request_filenamesuffix = key_gen_browsers[known_browsers[browsertype]]

##############################################################################
# Zusaetzliche Ueberpruefungen diverser Parameter
##############################################################################

if 'commonName' in form.inputkeys:
  commonName   = form.field.get('commonName',[''])[0].content
else:
  commonName = ''
if 'emailAddress' in form.inputkeys:
  emailAddress   = form.field.get('emailAddress',[''])[0].content
else:
  emailAddress = ''

# Check for "internal" mail domain
if (ca_name in caInternalCertTypes) and \
   not (DomainAdr(emailAddress) in caInternalDomains):
  htmlbase.PrintErrorMsg('This type of certificate request is restricted to internal address domains!')
  sys.exit(0)

if not (RequestDataKey in form.inputkeys and form.field[RequestDataKey][0].content):

  # Aufruf erfolgte mit Parametern ohne Schluessel =>
  # 1. Schritt: Eingegebene Daten anzeigen und
  # Benutzer zur Schluesselerzeugung auffordern

  PrintKeygenForm(form,ca_name,ca,browsertype)
  sys.exit(0)

# Aufruf erfolgte mit Parametern inkl. Schluessel =>
# 2. Schritt: Forminhalt bearbeiten

# Check the required key length if min_key_size was defined
if ca.min_key_size>0:
  # FIX ME!!!
  # This is a very primitive and falsy key length checking!!!
  # Only useful for SPKAC
  minbytes={512:200,768:300,1024:400}
  if minbytes.has_key(ca.min_key_size) and len(form.field[RequestDataKey][0].content)<minbytes[ca.min_key_size]:
    htmlbase.PrintErrorMsg('The key length you submitted was too weak!<BR>The certificate type <STRONG>%s</STRONG> requires a minimum key size of <STRONG>%d</STRONG> bits!' % (ca_name,ca.min_key_size))
    sys.exit(0)

# Zufaellige ChallengeID erzeugen und daraus eindeutige, noch nicht
# existierende Dateinamen mittels MD5-Hash basteln

import random, md5, binascii

# Zufaellige ID fuer Antwort vom Benutzer
caChallengeId = md5.new('%d' % random.randint(0,99999999))
formKeys = form.inputkeys[:]
for i in formKeys:
  for j in form.field[i]:
    caChallengeId.update(j.content)

# ca_name und ChallengeId fuer Mail-Subjects und Dateinamen
camailSubject    = 'cert-req-%s.%s.%s' % (RequestDataKey,ca_name,string.replace(binascii.b2a_base64(caChallengeId.digest()),'/','_')[:-1])
request_filename = os.path.join(ca.pend_reqs_dir,'%s.%s' % (camailSubject,request_filenamesuffix))

if os.path.exists(request_filename):
  # Versuch nicht existierenden Dateinamen zu basteln schlug fehl.
  # Duerfte eigentlich nicht passieren.
  htmlbase.PrintErrorMsg('Error generating a random ID or creating temporary files.')
  sys.exit(0)

##############################################################################
# Request erzeugen
##############################################################################

request_file = open(request_filename,'w')

if RequestDataKey=='PKCS10':

  request_file.write("""-----BEGIN CERTIFICATE REQUEST-----
  %s
-----END CERTIFICATE REQUEST-----
""" % (form.field['PKCS10'][0].content))

elif RequestDataKey=='SPKAC':

  # FIX ME! This won't work with additional parameters of [ new_oids ] section
#  CertRequestKeys = ['countryName','stateOrProvinceName','localityName','organizationName','organizationalUnitName','commonName','initials','uid','emailAddress','SPKAC']
  CertRequestKeys = filter(
    lambda i: not i in ['challenge','browsertype'],
    form.keys
  )
  for i in CertRequestKeys:
    if (i in form.inputkeys) and form.field[i][0].content:
      request_file.write('%s = %s\n' % (i,form.field[i][0].content))

request_file.close()
os.chmod(request_filename,0444)

##############################################################################
# Send a nice e-mail with random ID to user to initiate mail dialogue
##############################################################################

if caCertReqMailAdr and emailAddress:

  import smtplib, mimify

  if commonName:
    to_addr = '%s <%s>' % (mimify.mime_encode_header(commonName),emailAddress)
  else:
    to_addr = '%s' % (emailAddress)

  # Mailbody erzeugen
  mail_msg = """From: %s
To: %s
Subject: %s

Someone (maybe you) has sent a certificate request
to our certificate authority.

Please answer this e-mail with the same subject
if this was really you and the data below is correct.

If someone abused your name / e-mail address simply
forget about this message and delete it. %s

------------- Identity Information -------------
""" % (caCertReqMailAdr,\
       to_addr,\
       camailSubject,\
       (caPendCertReqValid>0)*(' The certificate\nrequest will be removed automatically after %d hours.' % caPendCertReqValid)
      )
  # Hier den eigentlichen Cert-Req an Mailbody anhaengen
  formKeys = form.keys[:]
  for unwantedkey in ['challenge','browsertype',RequestDataKey]:
    try:
      formKeys.remove(unwantedkey)
    except ValueError:
      pass

  mail_msg_paramlist = []
  for i in formKeys:
    if (i in form.inputkeys) and form.field[i][0].content:
      mail_msg_paramlist.append('%s = %s' % (i,form.field[i][0].content))
  mail_msg = '%s%s' % (mail_msg,string.join(mail_msg_paramlist,'\n'))

  try:
    smtpconn=smtplib.SMTP(MailRelay)
    smtpconn.set_debuglevel(0)
    try:
      smtpconn.sendmail(caCertReqMailAdr,[to_addr],mail_msg)
    except:
      htmlbase.PrintErrorMsg(
        'Unable to send an e-mail to <B>%s</B>!<BR>Please provide your correct and valid %s or ask your system administrator.' % \
        (
          charset.escapeHTML(to_addr),
          HelpURL(HelpUrlBase,'emailAddress','e-mail address')
        )
      )
      sys.exit(0)
    smtpconn.quit()
  except socket.error:
    htmlbase.PrintErrorMsg('Unable to contact default mail server!')
    sys.exit(0)

# Schliesslich und endlich...
htmlbase.PrintHeader('Certificate request stored.')
htmlbase.PrintHeading('Certificate request is stored.')
print """Your certificate request was stored for
further processing."""

if caCertReqMailAdr and emailAddress:
  print """<P>You will get an e-mail message with a random ID.
Please answer this e-mail to confirm your certificate request."""

if caPendCertReqValid:
  print """Otherwise your certificate request will be
removed automatically after %d hour(s).<P>""" % (caPendCertReqValid)

print '<P>Once again the data you gave to us:<P>'
PrintInput(form)
htmlbase.PrintFooter()

sys.exit(0)

