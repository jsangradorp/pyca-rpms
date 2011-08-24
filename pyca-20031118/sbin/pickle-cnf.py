#!/usr/bin/python

########################################################################
# pickle-cnf.py
# (c) by Michael Stroeder, michael@stroeder.com
########################################################################

__version__ = '0.6.6'

########################################################################
# This short script creates a pickled object file of the
# OpenSSL configuration file.
########################################################################

import sys, string, os, pickle, getopt

def findoption(options,paramname):
  for i in options:
    if i[0]==paramname:
      return i
  return ()

def PrintUsage(ErrorMsg='',ErrorCode=1):
  script_name = string.split(sys.argv[0],os.sep)[-1]
  sys.stderr.write("""*** %s *** (C) by Michael Stroeder, 1999

usage: %s [options]

Options:

  -h or --help
        Print out this message

  --config=[pathname]
	Pathname of OpenSSL configuration file.
        You may also use env variable OPENSSL_CONF.
	Default: /etc/openssl/openssl.cnf

  --pycalib=[directory]
        Specify directory containing the pyCA modules
        You may also use env variable PYCALIB.
	Default: /usr/local/pyca/pylib

""" % (script_name,script_name))
  if ErrorMsg:
    sys.stderr.write('Error: %s\n' % ErrorMsg)
  sys.exit(ErrorCode)

########################################################################
#                              Main
########################################################################

script_name=sys.argv[0]

try:
  options,args=getopt.getopt(sys.argv[1:],'h',['help','config=','pycalib='])
except getopt.error,e:
  PrintUsage(str(e))

if findoption(options,'-h')!=() or findoption(options,'--help')!=():
  PrintUsage()

if findoption(options,'--config')!=():
  opensslcnfname = findoption(options,'--config')[1]
else:
  opensslcnfname = os.environ.get('OPENSSL_CONF','/etc/openssl/openssl.cnf')

if not os.path.isfile(opensslcnfname):
  PrintUsage('Config file %s not found.' % (opensslcnfname))

if findoption(options,'--pycalib')!=():
  pycalib = findoption(options,'--pycalib')[1]
else:
  pycalib = os.environ.get('PYCALIB','/usr/local/pyca/pylib')

if not os.path.exists(pycalib) or not os.path.isdir(pycalib):
  PrintUsage('Module directory %s not exists or not a directory.' % (pycalib))

sys.path.append(pycalib)

try:
  import openssl
except ImportError:
  PrintUsage('Module openssl not found in directory %s!' % (pycalib))

print 'Reading source file %s...' % (opensslcnfname)
opensslcnf = openssl.cnf.OpenSSLConfigClass(opensslcnfname)

pickle_opensslcnfname = '%s.pickle' % (opensslcnfname)

#if os.path.isfile(pickle_opensslcnfname):
#  print 'Removing old pickle file %s' % (pickle_opensslcnfname)
#  os.remove(pickle_opensslcnfname)

print 'Write new pickled file %s...' % (pickle_opensslcnfname)
f=open(pickle_opensslcnfname,'wb')
pickle.dump(opensslcnf, f,1)
f.close()
