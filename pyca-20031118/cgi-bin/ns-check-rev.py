#!/usr/bin/python

"""
ns-check-rev.py
(c) by Michael Stroeder <michael@stroeder.com>

CGI-BIN for On-line checking of certificates -
a handler for URL in Netscape extension nsRevocationUrl.

Have look at a x509_extensions-section and the
attributes nsBaseUrl and nsRevocationUrl

Input:

PATH_INFO
- Name of CA in openssl.cnf (section [ca] of openssl.cnf)
QUERY_STRING
- Serial number of desired certificate
  max. 8 digits hexadecimal (32 Bit)

Examples:
  ns-check-rev.py/Persona?537A
  checks if certificate number 0x537A issued of CA "Persona" is valid

Output:

  Content-type: application/x-netscape-revocation
  0 if certificate is valid <=> V in index.txt
  1 if certificate is invalid
"""

Version='0.6.6'

import sys, os, string, re, pycacnf, htmlbase, openssl

from pycacnf import opensslcnf, pyca_section

# Ein paar Umgebungsvariablen auslesen, welche der Apache liefert
request_method  = os.environ['REQUEST_METHOD']
query_string    = os.environ['QUERY_STRING']
ca_name = os.environ.get('PATH_INFO','')[1:]

# Wir lesen rein gar nix von Standardeingabe => gleich dicht machen
sys.stdin.close()

# Hier die ueblichen Paranoid-Pruefungen der Parameter
rm = (re.compile('[0-9a-fA-F]+')).match(query_string)
if (request_method!='GET') or \
   (len(query_string)>8) or \
   not rm or \
   rm.group(0)!=query_string:
  # Skript nicht mit GET aufgerufen
  # Seriennummer mit mehr 32 Bit
  # Parameter war keine Hex-Nummer
  # => Kommentarloses Ende
  sys.exit(0)

if not ca_name:
  htmlbase.PrintErrorMsg('No certificate authority.')
  sys.exit(0)

if not opensslcnf.data['ca'].has_key(ca_name):
  # CA-Definition nicht in openssl-Konfiguration enthalten
  htmlbase.PrintErrorMsg('Unknown certificate authority "%s"!' % ca_name)
  sys.exit(0)

ca_section=opensslcnf.data[opensslcnf.data['ca'][ca_name]]
ca_dir = ca_section.get('dir','')
ca_database = string.replace(ca_section.get('database','$dir/index.txt'),'$dir',ca_dir)

# Hex-String in Integer wandeln
serialnumber=string.atoi(query_string,16)

# Eintrag suchen lassen
entry = openssl.db.GetEntrybySerial(ca_database,serialnumber)

# Header schreiben
print 'Content-type: application/x-netscape-revocation\n'

# Kein Zertifikat mit angegebener Nummer gefunden
if not entry:
  print 1
  sys.exit(0)

# Zertifikat gueltig <=> type-Feld ist 'V'
print not (entry and openssl.db.IsValid(entry))

#if entry[openssl.db.DB_type]==openssl.db.DB_TYPE_VAL:
#  print 0
#else:
#  print 1

sys.exit(0)

