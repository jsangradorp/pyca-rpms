"""
vbs.py - generate VBScript for cert enrollment with M$ Internet Explorer
c) by Michael Stroeder, michael@stroeder.com

Special thanks to:
- inspired code contributed by Jordi Floriach <jfloriach@afina.net>,
- VBScript function PrintVBSCryptoProvider() appears by courtesy of
  Michael Konietzka <ca-project@konietzka.de>
"""

__version__='0.6.6'

import sys, string

def PrintVBSXenrollObject(codebase='xenroll.dll'):
  """
  <OBJECT> for xenroll.dll
  """
  print """
<OBJECT
  classid="clsid:127698e4-e730-4e5c-a2b1-21490a70c8a1"
  sXEnrollVersion="5,131,3659,0"
  CODEBASE="%s"
  id="certHelper"
>
</OBJECT>
""" % (codebase)

def PrintVBSKeyGenCode(form):
  """
  Generate code for key generation in Internet Explorer
  """

  # Mapping von SPKAC- zu DN-Attributnamen
  spkac2DNname = {
    'countryName':'C',
    'stateOrProvinceName':'S',
    'localityName':'L',
    'organizationName':'O',
    'organizationalUnitName':'OU',
    'commonName':'CN',
    'emailAddress':'1.2.840.113549.1.9.1',
    'initials':'2.5.4.43',
    'uid':'0.9.2342.19200300.100.1.1',
    'userID':'0.9.2342.19200300.100.1.1',
  }

  formKeys = form.inputkeys[:]
  for unwantedkey in ['userpassword','challenge','browsertype','PKCS10']:
    try:
      formKeys.remove(unwantedkey)
    except ValueError:
      pass
  CertDN_list = []
  for i in formKeys:
    if (i in form.inputkeys) and form.field[i][0].content:
      CertDN_list.append('%s=%s' % (spkac2DNname.get(i,i),form.field[i][0].content))

  print """
Function GenTheKeyPair()

  Dim certHelper

  Set certHelper = CreateObject("CEnroll.CEnroll.2")
  if ( (Err.Number = 438) OR (Err.Number = 429) ) Then
    Err.Clear
    Set certHelper = CreateObject("CEnroll.CEnroll.1")
  End If

  Dim keyprov, key, prov, pkcs10data
  keyprov = document.KeyGenForm.KeySize.value
  key     = Mid(keyprov,1,1)
  prov    = Mid(keyprov,2)

  certHelper.providerType = 1
  certHelper.providerName = prov

  If key = "4" Then
    certHelper.GenKeyFlags = &h04000003
  Else
    certHelper.GenKeyFlags = &h02000003
  End If
  certHelper.HashAlgorithm = "MD5"
  certHelper.KeySpec = 1

  certHelper.EnableT61DNEncoding = True

  pkcs10data = certHelper.createPKCS10("%s", "")
  If (pkcs10data = Empty) Then
    Alert "Error " & Hex(Err) & ": Your credentials could not be generated."
  Else
    Alert "The following certificate request was generated:"&chr(13)&chr(10)&"%s"
    Document.KeyGenForm.PKCS10.value = pkcs10data
    Document.KeyGenForm.submit()
  End If
End Function

""" % (string.join(CertDN_list,';'),string.join(CertDN_list,'"&chr(13)&chr(10)&"'))

###########################################################################
# Generate code for installing certificate in Internet Explorers cert DB
###########################################################################

def PrintVBSCertInstallCode(subject,serial,notafterstr,cert):

  certlines = string.split(cert,'\n')[1:-2]
  certcode = string.join(certlines,'" & chr(10) & _\n              "')

  msgstr = """"The following certificate will be installed:" & chr(13) & chr(10) & _
    "Serial: %s" & chr(13) & chr(10) & _
    "Subject: %s" & chr(13) & chr(10) & _
    "Valid until: %s" & chr(13) & chr(10)
    """ % (serial,subject,notafterstr)

  print """
Function InstallPKCS7Cert()

  Dim certHelper

  Set certHelper = CreateObject("CEnroll.CEnroll.2")
  if ( (Err.Number = 438) OR (Err.Number = 429) ) Then
    Err.Clear
    Set certHelper = CreateObject("CEnroll.CEnroll.1")
  End If

  Dim PKCS7Cert
  PKCS7Cert = "%s"
  On Error Resume Next
  MsgBox %s

  err.clear
  certHelper.AcceptPKCS7(PKCS7Cert)
  If Err.Number <> 0 Then
    Alert "Error " & Hex(Err) & ": The certificate could not be installed."
  Else
    MsgBox "The certificate was successfully installed."
  End If

End Function

Call InstallPKCS7Cert()
""" % (certcode,msgstr)

###########################################################################
# Generate code for choosing cryptographic provider
# Derived from example code by Michael Konietzka <ca-project@konietzka.de>
###########################################################################

def PrintVBSCryptoProvider():
  print """
Sub KeySizeSelectList

  Dim certHelper

  Set certHelper = CreateObject("CEnroll.CEnroll.2")
  if ( (Err.Number = 438) OR (Err.Number = 429) ) Then
    Err.Clear
    Set certHelper = CreateObject("CEnroll.CEnroll.1")
  End If

  Dim i
  Dim providers()
  Dim KeySizeOption
  Dim cryptoprovider
  Dim DefaultKeySize
  Dim enhanced
  On Error Resume Next

  i = 0
  DefaultKeySize = 0
  certHelper.providerType = 1

  Do
    cryptoprovider = ""
    cryptoprovider = certHelper.enumProviders(i,0)
    If Len(cryptoprovider) = 0 Then
      Exit Do
    Else
      enhanced = InStr(1,cryptoprovider,"Enhanced",1)
      set KeySizeOption = document.createElement("OPTION")
      If enhanced = 0 Then
	KeySizeOption.text = "512 bit, " & cryptoprovider
	KeySizeOption.value = "2"&cryptoprovider
      Else
	KeySizeOption.text = "1024 bit, " & cryptoprovider
	KeySizeOption.value = "4" & cryptoprovider
	document.KeyGenForm.KeySize.add(KeySizeOption)
	DefaultKeySize = i
	i = i+1
	set KeySizeOption = document.createElement("OPTION")
	KeySizeOption.text = "512 bit, " & cryptoprovider
	KeySizeOption.value = "2" & cryptoprovider
      End If
      document.KeyGenForm.KeySize.add(KeySizeOption)
    End If
      i = i+1
  Loop

  document.KeyGenForm.KeySize.DefaultKeySizeIndex = DefaultKeySize

  End Sub
"""
