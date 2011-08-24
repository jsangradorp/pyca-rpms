"""
pycacnf.py - Read OpenSSL configuration file openssl.cnf
(c) by Michael Stroeder <michael@stroeder.com>
"""

__version__ = '0.6.6'

import os

########################################################################
# Some variables for configuration
########################################################################

# Full pathname of OpenSSL configuration file,
# most times named openssl.cnf
cnf_filename = '/etc/openssl/openssl.cnf'

# List of additional module directories
pylib = [
  os.environ.get('PYCALIB','/usr/local/pyca/pylib'),
  '/home/michael/Proj/python/pyca/pylib'
]

########################################################################
# There's nothing to configure below this line
########################################################################

import sys,os

# Extend the Python path
sys.path.extend(pylib)

if os.path.isfile('%s.pickle' % (cnf_filename)):

  # Try to read OpenSSL's config file from a pickled copy
  f=open('%s.pickle' % (cnf_filename),'rb')
  try:
    # first try to use the faster cPickle module
    from cPickle import load
  except ImportError:
    from pickle import load
  opensslcnf=load(f)
  f.close()

else:
  # Read OpenSSL's config file from source
  import openssl
  opensslcnf=openssl.cnf.OpenSSLConfigClass(cnf_filename)

# Diverse allgemeine Parameter aus der Sektion [ pyca ] uebernehmen
pyca_section = opensslcnf.data.get('pyca',{})

import htmlbase

htmlbase.bodyPARAM=pyca_section.get('htmlBodyParam','')

ErrorLog = pyca_section.get('ErrorLog','')
if ErrorLog:
  # Redirect error log to defined file
  # FIX ME! File locking for concurrent access needed?
  sys.stderr.flush()
  sys.stderr = open(ErrorLog,'a')
