########################################################################
# Funktionen fuer immer wiederkehrende HTML-Ausgaben
########################################################################

########################################################################
# Hier einige Variablen zur Konfiguration
########################################################################

# Parameter fuers <BODY>-Tag
bodyPARAM=''

import os, string

# Ausgabe einer Ueberschrift
def PrintHeading(Msg,Type=1):
  print '<h%d>%s</h%d>' % (Type,Msg,Type)

# Ausdrucken eines HTML-Kopfes mit Titelzeile
def PrintHeader(TitleMsg,HTTP_charset='iso-8859-1'):
  print """Content-type: text/html;charset=%s
pragma: no-cache

<html>
<head>
  <title>%s</title>
  <meta name="generator" content="pyCA, see www.pyca.de"/>
</head>
<body %s>
""" % (HTTP_charset,TitleMsg,bodyPARAM)
  return

# Ausdrucken eines HTML-Endes
def PrintFooter():
  print """
  <p align=center>
    <font size=-2>
      Powered by
      <a href="http://www.pyca.de/" target="_pyca">pyCA</a>
    </font>
  </p>
</body>
</html>
"""
  return

# Fehlernachricht ausgeben
def PrintErrorMsg(Msg):
  PrintHeader('Error')
  print """<H1>Error</H1>
%s<P>
""" % (Msg)
  server_admin = os.environ.get('SERVER_ADMIN','')
  if server_admin:
    print 'Please contact <A HREF="mailto:%s">%s</A>.' % (
      server_admin,server_admin
    )
  PrintFooter()
  return

