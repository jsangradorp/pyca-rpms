##############################################################################
# cgissl.py 0.4.1
# (C) 1998 by Michael Stroeder
##############################################################################
# This module is distributed under the terms of the
# GPL (GNU GENERAL PUBLIC LICENSE) Version 2
# (see http://www.gnu.org/copyleft/gpl.html)
##############################################################################

import sys, os, re, string, charset

def GetAllSSLEnviron():

  SSLEnv = {}

  HTTPS = os.environ.get('HTTPS','off')
  if HTTPS=='on':

    SSLEnv['SSL_CIPHER_ALGKEYSIZE'] = \
      os.environ.get('SSL_CIPHER_ALGKEYSIZE',
      os.environ.get('HTTPS_KEYSIZE',
      os.environ.get('SSL_KEYSIZE',
      os.environ.get('SSL_SERVER_KEY_SIZE',
      ''))))
    SSLEnv['SSL_CIPHER_EXPORT'] = \
      os.environ.get('SSL_CIPHER_EXPORT',
      os.environ.get('HTTPS_EXPORT',
      os.environ.get('SSL_EXPORT',
      '')))
    SSLEnv['SSL_CIPHER'] = \
      os.environ.get('SSL_CIPHER',
      os.environ.get('HTTPS_CIPHER',
      ''))
    SSLEnv['SSL_CIPHER_USEKEYSIZE'] = \
      os.environ.get('SSL_CIPHER_USEKEYSIZE',
      os.environ.get('HTTPS_SECRETKEYSIZE',
      os.environ.get('SSL_SECKEYSIZE',
      '')))
    SSLEnv['SSL_CLIENT_A_SIG'] = \
      os.environ.get('SSL_CLIENT_A_SIG',
      os.environ.get('SSL_CLIENT_SIGNATURE_ALGORITHM',
      ''))
    SSLEnv['SSL_CLIENT_CERT'] = \
      os.environ.get('SSL_CLIENT_CERT',
      os.environ.get('SSL_CLIENT_CERTIFICATE',
      ''))
    SSLEnv['SSL_CLIENT_I_DN'] = \
      os.environ.get('SSL_CLIENT_I_DN',
      os.environ.get('SSL_CLIENT_IDN',
      ''))
    SSLEnv['SSL_CLIENT_I_DN_CN'] = \
      os.environ.get('SSL_CLIENT_I_DN_CN',
      os.environ.get('SSL_CLIENT_ICN',
      ''))
    SSLEnv['SSL_CLIENT_I_DN_C'] = \
      os.environ.get('SSL_CLIENT_I_DN_C',
      os.environ.get('SSL_CLIENT_IC',
      ''))
    SSLEnv['SSL_CLIENT_I_DN_Email'] = \
      os.environ.get('SSL_CLIENT_I_DN_Email',
      os.environ.get('SSL_CLIENT_IEMAIL',
      ''))
    SSLEnv['SSL_CLIENT_I_DN_L'] = \
      os.environ.get('SSL_CLIENT_I_DN_L',
      os.environ.get('SSL_CLIENT_IL',
      ''))
    SSLEnv['SSL_CLIENT_I_DN_O'] = \
      os.environ.get('SSL_CLIENT_I_DN_O',
      os.environ.get('SSL_CLIENT_IO',
      ''))
    SSLEnv['SSL_CLIENT_I_DN_OU'] = \
      os.environ.get('SSL_CLIENT_I_DN_OU',
      os.environ.get('SSL_CLIENT_IOU',
      ''))
    SSLEnv['SSL_CLIENT_I_DN_SP'] = \
      os.environ.get('SSL_CLIENT_I_DN_SP',
      os.environ.get('SSL_CLIENT_ISP',
      ''))
    SSLEnv['SSL_CLIENT_M_SERIAL'] = \
      os.environ.get('SSL_CLIENT_M_SERIAL',
      os.environ.get('SSL_CLIENT_CERT_SERIAL',
      ''))
    SSLEnv['SSL_CLIENT_S_DN'] = \
      os.environ.get('SSL_CLIENT_S_DN',
      os.environ.get('SSL_CLIENT_DN',
      ''))
    SSLEnv['SSL_CLIENT_S_DN_CN'] = \
      os.environ.get('SSL_CLIENT_S_DN_CN',
      os.environ.get('SSL_CLIENT_CN',
      ''))
    SSLEnv['SSL_CLIENT_S_DN_C'] = \
      os.environ.get('SSL_CLIENT_S_DN_C',
      os.environ.get('SSL_CLIENT_C',
      ''))
    SSLEnv['SSL_CLIENT_S_DN_Email'] = \
      os.environ.get('SSL_CLIENT_S_DN_Email',
      os.environ.get('SSL_CLIENT_EMAIL',
      ''))
    SSLEnv['SSL_CLIENT_S_DN_L'] = \
      os.environ.get('SSL_CLIENT_S_DN_L',
      os.environ.get('SSL_CLIENT_L',
      ''))
    SSLEnv['SSL_CLIENT_S_DN_O'] = \
      os.environ.get('SSL_CLIENT_S_DN_O',
      os.environ.get('SSL_CLIENT_O',
      ''))
    SSLEnv['SSL_CLIENT_S_DN_OU'] = \
      os.environ.get('SSL_CLIENT_S_DN_OU',
      os.environ.get('SSL_CLIENT_OU',
      ''))
    SSLEnv['SSL_CLIENT_S_DN_SP'] = \
      os.environ.get('SSL_CLIENT_S_DN_SP',
      os.environ.get('SSL_CLIENT_SP',
      ''))
    SSLEnv['SSL_CLIENT_V_END'] = \
      os.environ.get('SSL_CLIENT_V_END',
      os.environ.get('SSL_CLIENT_CERT_END',
      ''))
    SSLEnv['SSL_CLIENT_V_START'] = \
      os.environ.get('SSL_CLIENT_V_START',
      os.environ.get('SSL_CLIENT_CERT_START',
      ''))
    SSLEnv['SSL_PROTOCOL'] = \
      os.environ.get('SSL_PROTOCOL',
      os.environ.get('SSL_PROTOCOL_VERSION',
      ''))
    SSLEnv['SSL_SERVER_A_SIG'] = \
      os.environ.get('SSL_SERVER_A_SIG',
      os.environ.get('SSL_SERVER_SIGNATURE_ALGORITHM',
      ''))
    SSLEnv['SSL_SERVER_CERT'] = \
      os.environ.get('SSL_SERVER_CERT',
      os.environ.get('SSL_SERVER_CERTIFICATE',
      ''))
    SSLEnv['SSL_SERVER_I_DN_CN'] = \
      os.environ.get('SSL_SERVER_I_DN_CN',
      os.environ.get('SSL_SERVER_ICN',
      ''))
    SSLEnv['SSL_SERVER_I_DN_C'] = \
      os.environ.get('SSL_SERVER_I_DN_C',
      os.environ.get('SSL_SERVER_IC',
      ''))
    SSLEnv['SSL_SERVER_I_DN_Email'] = \
      os.environ.get('SSL_SERVER_I_DN_Email',
      os.environ.get('SSL_SERVER_IEMAIL',
      ''))
    SSLEnv['SSL_SERVER_I_DN_L'] = \
      os.environ.get('SSL_SERVER_I_DN_L',
      os.environ.get('SSL_SERVER_IL',
      ''))
    SSLEnv['SSL_SERVER_I_DN_O'] = \
      os.environ.get('SSL_SERVER_I_DN_O',
      os.environ.get('SSL_SERVER_IO',
      ''))
    SSLEnv['SSL_SERVER_I_DN'] = \
      os.environ.get('SSL_SERVER_I_DN',
      os.environ.get('SSL_SERVER_IDN',
      ''))
    SSLEnv['SSL_SERVER_I_DN_OU'] = \
      os.environ.get('SSL_SERVER_I_DN_OU',
      os.environ.get('SSL_SERVER_IOU',
      ''))
    SSLEnv['SSL_SERVER_I_DN_SP'] = \
      os.environ.get('SSL_SERVER_I_DN_SP',
      os.environ.get('SSL_SERVER_ISP',
      ''))
    SSLEnv['SSL_SERVER_M_SERIAL'] = \
      os.environ.get('SSL_SERVER_M_SERIAL',
      os.environ.get('SSL_SERVER_CERT_SERIAL',
      ''))
    SSLEnv['SSL_SERVER_S_DN'] = \
      os.environ.get('SSL_SERVER_S_DN',
      os.environ.get('SSL_SERVER_DN',
      ''))
    SSLEnv['SSL_SERVER_S_DN_CN'] = \
      os.environ.get('SSL_SERVER_S_DN_CN',
      os.environ.get('SSL_SERVER_CN',
      ''))
    SSLEnv['SSL_SERVER_S_DN_C'] = \
      os.environ.get('SSL_SERVER_S_DN_C',
      os.environ.get('SSL_SERVER_C',
      ''))
    SSLEnv['SSL_SERVER_S_DN_Email'] = \
      os.environ.get('SSL_SERVER_S_DN_Email',
      os.environ.get('SSL_SERVER_EMAIL',
      ''))
    SSLEnv['SSL_SERVER_S_DN_L'] = \
      os.environ.get('SSL_SERVER_S_DN_L',
      os.environ.get('SSL_SERVER_L',
      ''))
    SSLEnv['SSL_SERVER_S_DN_O'] = \
      os.environ.get('SSL_SERVER_S_DN_O',
      os.environ.get('SSL_SERVER_O',
      ''))
    SSLEnv['SSL_SERVER_S_DN_OU'] = \
      os.environ.get('SSL_SERVER_S_DN_OU',
      os.environ.get('SSL_SERVER_OU',
      ''))
    SSLEnv['SSL_SERVER_S_DN_SP'] = \
      os.environ.get('SSL_SERVER_S_DN_SP',
      os.environ.get('SSL_SERVER_SP',
      ''))
    SSLEnv['SSL_SERVER_V_END'] = \
      os.environ.get('SSL_SERVER_V_END',
      os.environ.get('SSL_SERVER_CERT_END',
      ''))
    SSLEnv['SSL_SERVER_V_START'] = \
      os.environ.get('SSL_SERVER_V_START',
      os.environ.get('SSL_SERVER_CERT_START',
      ''))
    SSLEnv['SSL_VERSION_LIBRARY'] = \
      os.environ.get('SSL_VERSION_LIBRARY',
      os.environ.get('SSL_SSLEAY_VERSION',
      ''))

  return SSLEnv



##############################################################################
# Determine Security Level
##############################################################################

def SecLevel(acceptedciphers,valid_dn_regex='',valid_idn_regex=''):

  SSL_CIPHER = os.environ.get('SSL_CIPHER',
               os.environ.get('HTTPS_CIPHER',
	       ''))

  # SSL-Verbindung?
  if SSL_CIPHER and (SSL_CIPHER in acceptedciphers):

    SSL_CLIENT_S_DN = os.environ.get('SSL_CLIENT_S_DN',
		      os.environ.get('SSL_CLIENT_DN',
		      ''))

    if SSL_CLIENT_S_DN:

      SSL_CLIENT_I_DN = os.environ.get('SSL_CLIENT_I_DN',
			os.environ.get('SSL_CLIENT_IDN',
			''))

      dn_rm = re.compile(valid_dn_regex).match(SSL_CLIENT_S_DN)
      idn_rm = re.compile(valid_idn_regex).match(SSL_CLIENT_I_DN)
    
      if (dn_rm) and \
	 (idn_rm):
	return 2
      else:  
	return 1

    else:  
      return 1

  return 0


##############################################################################
# Print the SSL data in HTML format
##############################################################################

def PrintSecInfo(acceptedciphers,valid_dn_regex='',valid_idn_regex='',f=sys.stdout):

  seclevel = SecLevel(acceptedciphers,valid_dn_regex,valid_idn_regex)

  f.write("""<h3>Security level</h3><p>Current security level is: <strong>%d</strong></p>
           <table cellspacing=5%%>
	   <tr>
	     <td align=center width=10%%>0</td>
	     <td>no encryption at all</td>
	   </tr>
	   <tr>
	     <td align=center>1</td>
	     <td>Session is encrypted with SSL and cipher is accepted</td>
	   </tr>
	   <tr>
	     <td align=center>2</td>
	     <td>Client presented valid certificate,<br>
	     the DN of the certified object matches "<CODE>%s</CODE>"<br>
	     and the DN of the certifier matches "<CODE>%s</CODE>"</td>
	   </tr>
	   </table>
	   """ % (seclevel,valid_dn_regex,valid_idn_regex))

  if seclevel>=1:

    SSL_CIPHER_ALGKEYSIZE = os.environ.get('SSL_CIPHER_ALGKEYSIZE',
                            os.environ.get('HTTPS_KEYSIZE',
			    os.environ.get('SSL_KEYSIZE',
			    os.environ.get('SSL_SERVER_KEY_SIZE',
			    ''))))
    SSL_CIPHER_EXPORT = os.environ.get('SSL_CIPHER_EXPORT',
                	os.environ.get('HTTPS_EXPORT',
			os.environ.get('SSL_EXPORT',
			'')))
    SSL_CIPHER = os.environ.get('SSL_CIPHER',
        	 os.environ.get('HTTPS_CIPHER',
		 ''))
    SSL_CIPHER_USEKEYSIZE = os.environ.get('SSL_CIPHER_USEKEYSIZE',
                            os.environ.get('HTTPS_SECRETKEYSIZE',
			    os.environ.get('SSL_SECKEYSIZE',
			    '')))
    SSL_SERVER_S_DN = os.environ.get('SSL_SERVER_S_DN',
		      os.environ.get('SSL_SERVER_DN',
		      ''))
    SSL_SERVER_I_DN = os.environ.get('SSL_SERVER_I_DN',
		      os.environ.get('SSL_SERVER_IDN',
		      ''))

    f.write("""You connected with cipher <strong>%s</strong>, key size <strong>%s Bit</strong>, actually used key size <strong>%s Bit</strong>.<p>
<h3>Server certificate</h3>
<table summary="Server certificate">
  <tr>
    <td>
      <dl>
	<dt>This certificate belongs to:</dt>
	<dd>%s</dd>
      </dl>
    </td>
    <td>
      <dl>
	<dt>This certificate was issued by:</dt>
	<dd>%s</dd>
      </dl>
    </td>
  </tr>
</table>
""" % (
  SSL_CIPHER,
  SSL_CIPHER_ALGKEYSIZE,
  SSL_CIPHER_USEKEYSIZE,
  string.join(string.split(charset.asn12html4(SSL_SERVER_S_DN),'/'),'<br>'),
  string.join(string.split(charset.asn12html4(SSL_SERVER_I_DN),'/'),'<br>')
))

  if seclevel>=2:

    SSL_CLIENT_I_DN = os.environ.get('SSL_CLIENT_I_DN',
			 os.environ.get('SSL_CLIENT_IDN',
			 ''))
    SSL_CLIENT_S_DN = os.environ.get('SSL_CLIENT_S_DN',
		      os.environ.get('SSL_CLIENT_DN',
		      ''))

    f.write("""<h3>Your client certificate</h3>
<table summary="Client certificate">
  <tr>
    <td>
      <dl>
	<dt>This certificate belongs to:</dt>
	<dd>%s</dd>
      </dl>
    </td>
    <td>
      <dl>
	<dt>This certificate was issued by:</dt>
	<dd>%s</dd>
      </dl>
    </td>
  </tr>
</table>
""" % (
  string.join(string.split(charset.asn12html4(SSL_CLIENT_S_DN),'/'),'<br>'),
  string.join(string.split(charset.asn12html4(SSL_CLIENT_I_DN),'/'),'<br>')
))

