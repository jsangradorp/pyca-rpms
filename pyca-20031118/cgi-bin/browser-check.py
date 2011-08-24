#!/usr/bin/python

"""
browser-check.py
(c) by Michael Stroeder <michael@stroeder.com>

CGI-BIN to check cryptographic abilities of a WWW
browser/server combination
The SSL data only works with the environment of ApacheSSL.
"""

Version='0.6.6'

########################################################################
# Some variables to configure the basic behaviour
########################################################################

# Do not list the environment vars listed here
hidden_envvars = [
  'DOCUMENT_ROOT','SCRIPT_NAME','SCRIPT_FILENAME','PATH',
  'SERVER_SOFTWARE','SSLEAY_VERSION','SERVER_SIGNATURE'
]

# Specifies a list of the acceptable symmetric key ciphers
# See also http://www.apache-ssl.org/ and the ApacheSSL
# run-time directives SSLBanCipher, SSLRequireCipher, SSLRequiredCiphers
sec_sslacceptedciphers = [
    'IDEA-CBC-SHA',
    'RC4-MD5',
    'RC4-SHA',
    'IDEA-CBC-MD5',
    'DES-CBC3-SHA',
    'DH-DSS-DES-CBC3-SHA',
    'DH-RSA-DES-CBC3-SHA',
    'EDH-DSS-DES-CBC3-SHA',
    'EDH-RSA-DES-CBC3-SHA',
    'ADH-RC4-MD5',
    'ADH-DES-CBC3-SHA',
    'FZA-RC4-SHA',
    'RC2-CBC-MD5',
    'DES-CBC3-MD5'
  ]

########################################################################
# There's nothing to configure below this line
########################################################################

import sys,os,string,time,re,urllib

import pycacnf,htmlbase,charset

###############################################################################
# Umgebungs-Variablen
###############################################################################

sys.stdin.close()

gmt=time.time()-3600*time.daylight+time.timezone

htmlbase.PrintHeader('Cryptographic Browser Check')
htmlbase.PrintHeading('Cryptographic Browser Check')

htmlbase.PrintHeading('SSL',2)

if os.environ.has_key('HTTPS'):

  htmlbase.PrintHeading('SSL symmetric cipher',3)
  print 'You connected with cipher <STRONG>%s</STRONG>, key size <STRONG>%s Bit</STRONG>, secret key size <STRONG>%s Bit</STRONG>.<P>' % (
          os.environ['SSL_CIPHER'],
	  os.environ['HTTPS_KEYSIZE'],
	  os.environ['HTTPS_SECRETKEYSIZE']
	)

  htmlbase.PrintHeading('Client Certificate',3)
  ssl_client_dn = os.environ.get('SSL_CLIENT_DN','')
  if ssl_client_dn:
    ssl_client_idn = os.environ.get('SSL_CLIENT_I_DN','')
    if not ssl_client_idn:
      ssl_client_idn = os.environ.get('SSL_CLIENT_IDN','')
    print 'Your client sent the following certificate:<TABLE BORDER=1><TR><TD>%s</TD><TD>%s</TD></TR></TABLE><P>' % (
	   string.join(string.split(charset.t612html4(ssl_client_dn[1:]),'/'),'<BR>'),
	   string.join(string.split(charset.t612html4(ssl_client_idn[1:]),'/'),'<BR>')
	  )
  else:
    print 'Your client did not send a certificate or the server did not request a client certificate.'

else:
  print 'This was not a SSL connection at all.'

htmlbase.PrintHeading('Test Key Generation',2)
query_string=os.environ.get('QUERY_STRING','')

if query_string:
  spkac_rm=re.compile('^SPKAC=.*').match(query_string)
  if spkac_rm and spkac_rm.string==query_string:
    spkac_req=urllib.unquote_plus(query_string[6:])
    print 'Your client submitted the following SPKAC request (%d Bytes):<PRE>%s</PRE>' % (len(spkac_req),spkac_req)
  else:
    print 'The format of the submitted SPKAC request was wrong.'
else:
  print """
  <FORM ACTION="browser-check.py" METHOD="GET">
    Key length: <KEYGEN NAME="SPKAC" CHALLENGE="test">
    <INPUT TYPE="submit" VALUE="Generate Key Pair">
  </FORM>
  """

htmlbase.PrintHeading('Environment Variables')
print '<TABLE BORDER>'
env_keys=os.environ.keys()

hidden_envvars.append('QUERY_STRING')
for env in hidden_envvars:
  try:
    env_keys.remove(env)
  except ValueError:
    pass
env_keys.sort()

for env in env_keys:
  if env[0:4]!='SSL_':
    print '<TR><TD>%s</TD><TD>%s</TD></TR>' % (env,os.environ[env])
print '</TABLE>'

htmlbase.PrintFooter()

sys.exit(0)
