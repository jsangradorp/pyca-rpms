#######################################################################
# openssl.db.py Version 0.6.4
# (c) by Michael Stroeder, michael.stroeder@propack-data.de
########################################################################
# Module for OpenSSL certificate database
########################################################################

import openssl

import sys, os, string, time, re, charset

# Konstanten aus SSLeay/apps/ca.c

DB_type     = 0
DB_exp_date = 1
DB_rev_date = 2
DB_serial   = 3       # index - unique
DB_file     = 4
DB_name     = 5       # index - unique for active
DB_number   = 6

DB_TYPE_REV = 'R'
DB_TYPE_EXP = 'E'
DB_TYPE_VAL = 'V'

# Struktur eines DN
# /C=ISO-Laendercode
# /ST=Bundesstaat
# /L=Ort
# /O=Organisation
# /OU=Abteilung
# /CN=Common Name
# /Email=Mailadresse

empty_DN_dict = {'C':'','ST':'','L':'','O':'','OU':'','CN':'','Email':''}


##############################################################################
# Eintrag aus der database mittels serial suchen
# Eingabe:
#   Seriennummer des Zertifikats als int
# Ergebnis:
#   Liste mit Feldern des Eintrags, falls vorhanden
#   [], falls kein Eintrag mit angegebener
#       Seriennummer gefunden wurde
##############################################################################

def GetEntrybySerial(db_filename,serial):

  # Oeffnen der SSLeay-Zertifikatliste
  database=open(db_filename,'r')

  # Zeile mit serial suchen
  dbline=string.strip(database.readline())
  while dbline:
    dbfields=string.split(dbline,'\t')
    dbserial=string.atoi(dbfields[DB_serial],16)

    if dbserial==serial:
      # Zertifikat mit angegebener Nummer gefunden
      return dbfields
    dbline=database.readline()

  # keine passende Zeile gefunden
  return []


##############################################################################
# DN auseinandernehmen
# Ergebnis ist Dictionary mit Feldnamen als Keys (siehe empty_DN_dict)
##############################################################################

def SplitDN(DN):

  result = {}
  s = string.split(DN[1:],'/')
  for i in s:
    try:
      id,value = string.split(i,'=',1)
      result[id] = value
    except:
      pass
  return result


##############################################################################
# Ueberpruefen, ob Eintrag dbfields (Liste der DB-Felder) noch gueltig ist.
# 1 falls gueltig, 0 falls abgelaufen oder widerrufen
##############################################################################

def IsValid(db_entry):

  # Aktuelle Zeit in GMT abholen
  gmt = time.time()
  exp_time = time.mktime(dbtime2tuple(db_entry[DB_exp_date]))

  return (db_entry[DB_type]==DB_TYPE_VAL) and (exp_time > gmt)


##############################################################################
# Eintrag aus der database mittels DN suchen:
# Gesucht wird nach Feldern, welche als Substring, die jeweilige
# Angabe haben.
# Eingabe:
#   DN:
#     Dictionary mit Suchstrings (regulaere Ausdruecke)
#     Umlaute ISO-codiert
#   casesensitive:
#     Gibt an, ob Gross-/Kleinschreibung beachtet werden soll.
#   onlyvalid:
#     Es werden nur gueltige Zertifikate gesucht, d.h. das Feld DB_type
#     muss DB_TYPE_VAL enthalten und das Expire-Datum wird gleich geprueft.
#
# Ergebnis:
#   Liste mit Eintragslisten, falls gefunden
#   [], falls kein Eintrag mit angegebenen
#       Attributen gefunden wurde
#   [], falls keine Suchmuster angegeben wurden
##############################################################################

def GetEntriesbyDN(db_filename,DN=empty_DN_dict,casesensitive=0,onlyvalid=0):

  searchcounter = 0
  searchindex    = []
  searchregex    = {}

  for i in DN.keys():

    if DN[i]!='':
      # Liste mit Indizes der angegebenen Suchfelder
      searchindex.append(i)
      # Liste mit kompilierten regex
      if not casesensitive:
        DN[i]=string.lower(DN[i])
      searchregex[i] = re.compile(DN[i])
      # Angegebene Suchfelder zaehlen
      searchcounter  = searchcounter + 1

  # Keinerlei Suchangabe => leere Liste
  if searchcounter==0:
    return[]

  # Oeffnen der SSLeay-Zertifikatliste
  db_file=open(db_filename,'r')

  # Liste der gefundenen Eintraege
  found = []

  # Erste Zeile lesen und LF abschneiden
  db_line=string.strip(db_file.readline())

  while db_line:

    # Eintragszeile auseinandernehmen
    db_entry = string.split(db_line,'\t')
    # DN-Feld auseinander nehmen
    dnfield  = SplitDN(db_entry[DB_name])

    # Alle Teile des DN-Feldes mit jeweiligem Suchmuster vergleichen
    matchcounter = 0
    for i in searchindex:
      if dnfield.has_key(i):
        dnfield[i] = charset.asn12iso(dnfield[i])
        if not casesensitive:
	  dnfield[i] = string.lower(dnfield[i])
        matchcounter = matchcounter+(searchregex[i].search(dnfield[i])!=None)

    # Alle Angaben gefunden?
    if matchcounter==searchcounter:
      if onlyvalid:
        if IsValid(db_entry):
          found.append(db_entry)
      else:
        found.append(db_entry)

    # naechste Zeile lesen und LF abschneiden
    db_line=db_file.readline()[:-1]

  # keine passende Zeile gefunden
  return found


########################################################################
# Konvertieren einer Zeitangabe in der SSLeay-DB in ein Python-Tupel
# kompatibel zum Modul time.
# Eingabe:
#   openssltime	Zeitangabe aus SSLeay-DB als String
# Augabe:
#   konvertiertes time-Tupel als Funktionsergebnis
########################################################################

def dbtime2tuple(openssltime):

  # return time.strptime(openssltime,'%y%m%d%H%M%SZ')
  # would be easier but since strptime is broken in glibc...

  openssltime=openssltime[:-1]

  year  = string.atoi(openssltime[0:2])
  # Ja, diese Software ist Y2K ;-)
  if year<50:
    year=year+2000
  else:
    year=year+1900
  month = string.atoi(openssltime[2:4])
  day   = string.atoi(openssltime[4:6])
  hour  = string.atoi(openssltime[6:8])
  minute  = string.atoi(openssltime[8:10])
  if len(openssltime)>10:
    second = string.atoi(openssltime[10:12])
  else:
    second = 0

  return (year,month,day,hour,minute,second,0,0,0)

########################################################################
# Ein Zertifikat mit der angegebenen Seriennr. zurueckrufen, also
# DB_type-Feld auf DB_TYPE_REV = 'R' setzen.
# Eingabe
#   serial	eine Ganzzahl mit der Seriennr.
#               oder eine Liste mit Seriennr.
#               der zu widerrufenden Zertifikate
########################################################################

def Revoke(db_filename,serial):

  # Umbenennen der Datei
  os.rename(db_filename,db_filename+'.old')

  # Oeffnen der alten SSLeay-Zertifikatliste zum Lesen
  db_old=open(db_filename+'.old','r')

  # Erzeugen der neuen SSLeay-Zertifikatliste zum Schreiben
  db_new=open(db_filename,'w')

  # Aktuelle Zeit in GMT abholen und in passenden String formatieren
  gmtstr = time.strftime('%y%m%d%H%M%SZ',time.gmtime(time.time()))

  # Erste Zeile aus alter Datei lesen
  db_line = string.strip(db_old.readline())

  while db_line:

    # Eintragszeile auseinandernehmen
    db_entry = string.split(db_line,'\t')

    # Ist das Zertifikat noch als gueltig markiert?
    if ((type(serial)==type([]) and \
        string.atoi(db_entry[DB_serial],16) in serial) \
         or \
       string.atoi(db_entry[DB_serial],16)==serial):

      # Zertifikat als abgelaufen markieren
      db_entry[DB_type] = DB_TYPE_REV
      # Zertifikat als abgelaufen markieren
      db_entry[DB_rev_date] = gmtstr

    # Eintragszeile in neue Datei schreiben
    db_new.write('%s\n' % string.join(db_entry,'\t'))

    # Naechste Zeile aus alter Datei lesen
    db_line = string.strip(db_old.readline())

  db_old.close()
  db_new.close()

########################################################################
# Alle Eintraege durchsuchen und DB_type-Feld auf DB_TYPE_EXP = 'E'
# setzen, falls Gueltigkeitsdauer des Zertifikats abgelaufen ist.
# Als Ergebnis eine Liste der abgelaufenen DB-Eintraege zurueckliefern.
# Falls db_write=0, dann werden keine Schreibaktionen ausgefuehrt.
########################################################################

def Expire(db_filename,db_expiretreshold=0,db_write=1):

  if db_write:
    # Umbenennen der Datei
    os.rename(db_filename,db_filename+'.old')
    # Oeffnen der alten SSLeay-Zertifikatliste zum Lesen
    db_old=open(db_filename+'.old','r')
    # Erzeugen der neuen SSLeay-Zertifikatliste zum Schreiben
    db_new=open(db_filename,'w')
  else:
    db_old=open(db_filename,'r')

  # Aktuelle Zeit in GMT abholen
  gmt = time.time()

  expired_db_entries = []

  # Erste Zeile aus alter Datei lesen
  db_line = string.strip(db_old.readline())

  while db_line:

    # Eintragszeile auseinandernehmen
    db_entry = string.split(db_line,'\t')

    # Ist das Zertifikat noch als gueltig markiert?
    if db_entry[DB_type]==DB_TYPE_VAL:

      exp_time = time.mktime(dbtime2tuple(db_entry[DB_exp_date]))

      # Zertifikat abgelaufen?
      if exp_time < gmt+db_expiretreshold:
        if db_write:
	  db_entry[DB_type] = DB_TYPE_EXP
	expired_db_entries.append(db_entry)

    if db_write:
      # Eintragszeile in neue Datei schreiben
      db_new.write('%s\n' % string.join(db_entry,'\t'))

    # Naechste Zeile aus alter Datei lesen
    db_line = string.strip(db_old.readline())

  db_old.close()
  if db_write:
    db_new.close()
  
  return expired_db_entries

########################################################################
# Objektklasse fuer eine Konfigurationsdatei
########################################################################

class OpenSSLcaDatabaseClass:

  def __init__(self,pathname):
    self.pathname = pathname

  def Expire(self):
    return Expire(self.pathname)

  def ExpireWarning(self,treshold):
    return Expire(self.pathname,db_expiretreshold=treshold,db_write=0)

  def Revoke(self,serial):
    Revoke(self.pathname,serial)

  def GetEntriesbyDN(self,DN=empty_DN_dict,casesensitive=0,onlyvalid=0):
    return GetEntriesbyDN(self.pathname,DN,casesensitive,onlyvalid)

  def GetEntrybySerial(self,serial):
    return GetEntrybySerial(self.pathname,serial)

