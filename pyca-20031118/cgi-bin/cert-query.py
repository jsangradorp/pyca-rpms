#!/usr/bin/python

"""
cert-query.py
(c) by Michael Stroeder <michael@stroeder.com>

CGI-BIN for querying the OpenSSL certificate DB
Outputs empty input form if queried without parameters.
"""

__version__ = '0.6.6'

import sys, os, string, re, \
       pycacnf, cgiforms, htmlbase, charset

from time import time,localtime,strftime,mktime

from pycacnf import opensslcnf, pyca_section

from openssl.db import \
  empty_DN_dict, \
  DB_type,DB_exp_date,DB_rev_date,DB_serial,DB_file,DB_name,DB_number, \
  DB_TYPE_REV,DB_TYPE_EXP,DB_TYPE_VAL, \
  dbtime2tuple,GetEntriesbyDN,SplitDN

nsBaseUrl    = pyca_section.get('nsBaseUrl','/')
nsGetCertUrl = pyca_section.get('nsGetCertUrl','get-cert.py')
nsViewCertUrl = pyca_section.get('nsViewCertUrl','view-cert.py')
ScriptMethod = pyca_section.get('ScriptMethod','POST')
HelpUrl      = pyca_section.get('HelpUrl',nsBaseUrl)
searchkeys = ['CN','Email','L','O','OU','ST','C']
optionkeys = ['casesensitive','onlyvalid','emailcerts','servercerts']

##############################################################################
# haeufig gebrauchte Funktionen
##############################################################################

# String der Hilfe-URL zu bestimmtem Parameter zurueckgeben
def HelpURL(name,text):
  return '<A HREF="%sns-enroll-help.html#%s">%s</A>' % (HelpUrl,name,charset.iso2html4(text))

# Ausdrucken eines leeren Eingabeformulars
def PrintEmptyForm(form,method='POST'):

  print '<FORM ACTION="%s" METHOD="%s" ACCEPT-CHARSET="iso-8859-1">\n' % \
        (os.environ.get('SCRIPT_NAME','cert-query.py'),method)
  print '<TABLE NOBORDER><TR>'
  for i in optionkeys:
    print '<TD>%s</TD><TD>%s</TD>' % (form.field[i][0].inputfield(),HelpURL(form.field[i][0].name,form.field[i][0].text))
  print '</TR>\n</TABLE>\n<TABLE>'
  for i in searchkeys:
    print '<TR><TD WIDTH=20%%>%s:</TD><TD>%s</TD></TR>' % (HelpURL(form.field[i][0].name,form.field[i][0].text),form.field[i][0].inputfield())
  print """</TABLE>
<INPUT TYPE="submit" VALUE="Search">
<INPUT TYPE="reset" VALUE="Reset">
</FORM>"""

# Ausgabe der Ergebnistabelle
def PrintFound(form,found,cellpadding=2,width=100):

  print '<TABLE BORDER CELLPADDING=%d%% WIDTH=%d%%>' % (cellpadding,width)
  # Tabellenueberschriften ausgeben
  print '<TR><TH>CA name</TH><TH COLSPAN=3>Serial</TH><TH>valid<BR>until</TH>'
  for i in searchkeys:
    print '<TH><FONT SIZE=-1>%s</FONT></TH>' % (form.field[i][0].text)
  print '</TR>'

  # Tabelleninhalte
  for ca_name in found.keys():
    ca = opensslcnf.getcadata(ca_name)
    if ca.isservercert():
      certtype='server'
    else:
      certtype='email'
    for i in found[ca_name]:
      # Eine Tabellenzeile ausgeben
      print '<TR><TD>%s</TD>' % (ca_name)
      if i[DB_type]==DB_TYPE_REV:
        print '<TD>%s</TD><TD>&nbsp;</TD><TD><A HREF="%s%s/%s/%s?%s">View</A></TD><TD>revoked %s</TD>' % ( \
  	  i[DB_serial],
	  nsBaseUrl,nsViewCertUrl,ca_name,certtype,i[DB_serial],
	  strftime('%Y-%m-%d %H:%M',localtime(mktime(dbtime2tuple(i[DB_rev_date]))))
	)
      elif i[DB_type]==DB_TYPE_EXP:
        print '<TD>%s</TD><TD>&nbsp;</TD><TD><A HREF="%s%s/%s/%s?%s">View</A></TD><TD>expired %s</TD>' % ( \
	  i[DB_serial],
	  nsBaseUrl,nsViewCertUrl,ca_name,certtype,i[DB_serial],
	  strftime('%Y-%m-%d %H:%M',localtime(mktime(dbtime2tuple(i[DB_exp_date]))))
	)
      elif i[DB_type]==DB_TYPE_VAL:
        print '<TD>%s</TD><TD><A HREF="%s%s/%s/%s.crt?%s">Load</A></TD><TD><A HREF="%s%s/%s/%s?%s">View</A></TD><TD>%s</TD>' % ( \
	  i[DB_serial],
	  nsBaseUrl,nsGetCertUrl,ca_name,certtype,i[DB_serial],
	  nsBaseUrl,nsViewCertUrl,ca_name,certtype,i[DB_serial],
	  strftime('%Y-%m-%d %H:%M',localtime(mktime(dbtime2tuple(i[DB_exp_date]))))
	)
      else:
        raise ValueError
      dnfield = SplitDN(i[DB_name])
      # Spaltenelemente ausgeben
      for j in searchkeys:
	if dnfield.has_key(j) and dnfield[j]:
	  if j=="Email":
            print '<TD><FONT SIZE=-1><A HREF="mailto:%s">%s</A></FONT></TD>' % (dnfield[j],dnfield[j])
	  else:
            print '<TD><FONT SIZE=-1>%s</FONT></TD>' % charset.asn12html4(dnfield[j])
	else:
          # bei leeren Feldern Leerzeichen, damit Tabelle immer Raender hat
          print '<TD>&nbsp;</TD>'
      print '</TR>'

  print '</TABLE>'

  return

##############################################################################
# Hauptprogramm
##############################################################################

# form initialisieren
form = cgiforms.formClass(charset='iso-8859-1')

# Die gueltigen Inputattribute setzen
alphanumregex = '[0-9a-zA-Z\344\366\374\304\326\334\337ß.*?_ -]*'
mailadrregex = '[0-9a-zA-Z@.*?=/_ -]*'

form.add(cgiforms.formCheckboxClass('casesensitive','case sensitive','yes',0))
form.add(cgiforms.formCheckboxClass('onlyvalid','only valid','yes',1))
form.add(cgiforms.formCheckboxClass('emailcerts','search e-mail certificates','yes',1))
form.add(cgiforms.formCheckboxClass('servercerts','search server certificates','yes',0))
form.add(cgiforms.formInputClass('CN','Common Name',30,alphanumregex))
form.add(cgiforms.formInputClass('Email','E-Mail',40,mailadrregex))
form.add(cgiforms.formInputClass('OU','Organizational Unit',30,alphanumregex))
form.add(cgiforms.formInputClass('O','Organization',30,alphanumregex))
form.add(cgiforms.formInputClass('L','Location',30,alphanumregex))
form.add(cgiforms.formInputClass('ST','State / Province',30,alphanumregex))
form.add(cgiforms.formInputClass('C','Country',2,'[a-zA-Z?]'*2))

# Schon Parameter vorhanden?
if not form.contentlength:

  # Aufruf erfolgte ohne Parameter =>
  # 0. Schritt: leeres Eingabeformular ausgeben

  htmlbase.PrintHeader('Search certificates')
  htmlbase.PrintHeading('Search certificates')
  print """You can search for certificates in the
certificate database.<P>Just type in substrings or
regular expressions as search criteria."""
  PrintEmptyForm(form)
  htmlbase.PrintFooter()
  sys.exit(0)

# Aufruf erfolgte mit Parametern
try:
  form.getparams()
except cgiforms.formContentLengthException,e:
  htmlbase.PrintErrorMsg('Content length invalid.')
  sys.exit(0)
except cgiforms.formParamNameException,e:
  htmlbase.PrintErrorMsg('Unknown parameter "%s".' % (e.name))
  sys.exit(0)
except cgiforms.formParamContentException,e:
  htmlbase.PrintErrorMsg('Content of field "%s" has invalid format.' % (e.text))
  sys.exit(0)
except cgiforms.formParamStructException,e:
  htmlbase.PrintErrorMsg('Too many (%d) parameters for field "%s".' % (e.count,e.name))
  sys.exit(0)
except cgiforms.formParamLengthException,e:
  htmlbase.PrintErrorMsg('Content too long. Field "%s" has %d characters.' % (e.text,e.length))
  sys.exit(0)
except:
  htmlbase.PrintErrorMsg('Unknown exception.')
  sys.exit(0)

# Parameter sind ok

# Anfrage zurecht formatieren
query = empty_DN_dict

for i in searchkeys:
  query[i] = form.field[i][0].content

found ={}
old_db_filenames = []

if 'casesensitive' in form.inputkeys:
  casesensitive = form.field['casesensitive'][0].content=='yes'
else:
  casesensitive = 0
if 'onlyvalid' in form.inputkeys:
  onlyvalid = form.field['onlyvalid'][0].content=='yes'
else:
  onlyvalid = 1
if 'emailcerts' in form.inputkeys:
  emailcerts = form.field['emailcerts'][0].content=='yes'
else:
  emailcerts = 0
if 'servercerts' in form.inputkeys:
  servercerts = form.field['servercerts'][0].content=='yes'
else:
  servercerts = 0

ca_names = opensslcnf.sectionkeys.get('ca',[])

for ca_name in ca_names:

  ca = opensslcnf.getcadata(ca_name)

  # Ist der Zertifikattyp 'S/MIME for client use' ?
  if (emailcerts and ca.isemailcert()) or \
     (servercerts and ca.isservercert()):

    # Stammverzeichnis der CA
    # Zertifikat-DB schon vorher mal behandelt?
    if not ca.database in old_db_filenames:
      old_db_filenames.append(ca.database)
      if os.path.isfile(ca.database):
	# Anfrage starten
        try:
	  found[ca_name] = GetEntriesbyDN(
            ca.database,
            query,
            form.field['casesensitive'][0].content=='yes',
            form.field['onlyvalid'][0].content=='yes'
          )
        except re.error:
          htmlbase.PrintErrorMsg('Error parsing regular expression.')
          sys.exit(0)

# Nix gefunden!
if not found:
  htmlbase.PrintErrorMsg('No matching entries found.')
  sys.exit(0)

# Ausgabe des Suchergebnisses
htmlbase.PrintHeader('Search results')
PrintFound(form,found)
htmlbase.PrintFooter()

sys.exit(0)

