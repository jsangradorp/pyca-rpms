##############################################################################
# cgihelper.py Version 0.1.4
# (c) by Michael Stroeder, michael.stroeder@propack-data.de
##############################################################################
# Misc. stuff useful in CGI-BINs
##############################################################################

import sys, os, string, re

known_browsers = {
                   'MSIE':'Microsoft Internet Explorer',
		   'Mozilla':'Netscape Navigator',
		   'Lynx':'Lynx',
		   'Opera':'Opera',
		   'StarOffice':'StarOffice',
		   'NCSA_Mosaic':'NCSA Mosaic',
		   'NetPositive':'Net Positive'
                 }
known_browsers_rev = {}
for b in known_browsers.keys():
  known_browsers_rev[known_browsers[b]]=b

compatible_browsers = known_browsers.keys()
compatible_browsers.remove('Mozilla')

compatible_browsers_re = re.compile('(%s)[/ ]+([0-9.]*)' % string.join(compatible_browsers,'|'))
mozilla_re             = re.compile('(Mozilla)[/ ]+([0-9.]*)')

# This function trys to parse the HTTP_USER_AGENT environment variable
# set in CGI-BINs and returns the tuple (Browser,Version). I am not sure
# if this succeeds in every situation since most browsers have very obscure
# HTTP_USER_AGENT entries for compability reasons.
# The following browsers are known by name:
# Netscape	Netscape Navigator, Netscape Communicator)
# MSIE		MS Internet Explorer
# Opera		Opera browser from http://www.operasoftware.com/
# StarOffice	built-in browser of Star Office
# Lynx		the text-based browser Lynx
# NetPositive	Net Positive (BeOS)

def BrowserType(http_user_agent):

  if not http_user_agent:
    return ('','')

  else:
    browserrm = compatible_browsers_re.search(http_user_agent)
    if browserrm:
      return browserrm.groups()
    else:
      browserrm = mozilla_re.search(http_user_agent)
      if browserrm:
        return browserrm.groups()
      else:
        return ('','')

# Main

# Read and parse some CGI-BIN environment variables
http_user_agent = os.environ.get('HTTP_USER_AGENT','')
if http_user_agent:
  http_user_agent_type,http_user_agent_version = BrowserType(http_user_agent)

script_name     = os.environ.get('SCRIPT_NAME','')
request_method  = os.environ.get('REQUEST_METHOD')
remote_addr     = os.environ.get('REMOTE_ADDR')
path_info       = os.environ.get('PATH_INFO','')
