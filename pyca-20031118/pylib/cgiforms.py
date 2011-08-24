""" 
cgiforms.py - class library for handling <FORM> input
(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)

Klassen zum Behandeln <FORM>s und zu CGI-BINs uebermittelten Forminhalten

Anmerkungen:
- Eingabefelder mit gleichen name-Attributen werden logisch zusammengefasst
  und muessen in der selben Reihenfolge registriert und angegeben werden.
- Es werden nur Parameter aus dem QUERY_STRING (GET) oder einzelne
  Datensaetze vom Typ application/x-www-form-urlencoded (POST) als
  Parameter angenommen.
""" 

__version__ = '0.9.20'


import sys, os, types, string, re, urllib, charset


class formFieldClass:
  """
  Base class for all kind of single input fields.
  
  In most cases this class is not used directly
  since derivate classes for most types of input fields exist.
  """

  def __init__(
    self,
    name,		# Field name used in <INPUT NAME="..">
    text,		# User-friendly text describing this field
    maxlength=0,	# maximum lenght of parameter value [Bytes]
    pattern='',		# regex pattern of valid values either as string
    			# or tuple (pattern,options)
    default='',		# default value to be used in method inputfield()
    required=0,		# mark field as mandantory
    accesskey='',	# key for accessing this field to be displayed
                        # by method inputfield()
    multiple=0,		# allow multiple appearances of same parameter name
                        # and store parameter list in self.content
  ):
    self.name      = name
    self.text      = text
    self.maxlength = maxlength
    self.default    = default
    self.required   = required
    self.accesskey  = accesskey
    self.multiple   = multiple
    self.charset    = 'iso-8859-1'
    self.counter    = 0
    self.inputfield_template = r'%s'
    self.contentprint_template = r'%s'
    if multiple:
      self.content   = []
    else:
      self.content   = ''
    if type(pattern) is types.TupleType:
      patternstring, patternoptions = pattern
    else:
      patternstring, patternoptions = pattern, 0
    self.regex = re.compile('^%s$' % patternstring, patternoptions)

  def __accesskeyfield__(self):
    if self.accesskey:
      return 'accesskey="%s"' % (self.accesskey)
    else:
      return ''

  def __label__(self,label):
    if label:
      return '<label for="%s">%s</label>' % (self.name,self.text)
    else:
      return ''

  def setdefault(self,input):
    """
    Set the default of a input field.
    
    Mainly this is used if self.default shall be changed after
    initializing the field object.
    """
    self.default = input

  def put(self,input):
    """
    Store the user's input into the field object.

    This method can be used to modify the user's input
    before storing it into self.content.
    """
    if self.multiple and len(self.content)<self.multiple:
      if self.content:
        self.content.append(input)
      else:
        self.content = [input]
    else:
      self.content = input

  def setcharset(self,charset):
    """
    Define the character set of the user's input.
    """
    self.charset = charset

  def textprint(self):
    """
    Simple textual print output of self.content.
    """
    return self.content
    
  def __defaultprint__(self):
    """
    HTML output of self.content.
    """
    return charset.recode(charset.escapeHTML(self.default),self.charset,'html4')

  def contentprint(self):
    """
    HTML output of self.content using the print template
    in self.contentprint_template.
    """
    return self.contentprint_template % (
      charset.recode(
        charset.escapeHTML(self.content),
        self.charset,'html4'
      )
    )


class formTextareaClass(formFieldClass):
  """
  <TEXTAREA>
  """

  def __init__(
    self,
    name,
    text,
    maxlength=0,
    pattern='',
    default='',
    required=0,
    accesskey='',
    multiple=0,
    rows=10,
    cols=60
  ):
    formFieldClass.__init__(self,name,text,maxlength,(pattern,re.M+re.S),default,required,accesskey,multiple)
    self.rows  = rows
    self.cols  = cols

  def inputfield(self,escape_html_chars='<>":={}()',label=0):
    """
    Input field.
    """
    return self.__label__(label)+self.inputfield_template % (
      '<textarea id="%s" name="%s" %s rows="%d" cols="%d">%s</textarea>' % (
        self.name,
	self.name,
	self.__accesskeyfield__(),
	self.rows,self.cols,
	self.__defaultprint__()
      )
    )


class formInputClass(formFieldClass):
  """
  <INPUT>
  """

  def __init__(self,name,text,maxlength=0,pattern='',default='',required=0,accesskey='',multiple=0,size=0):
    formFieldClass.__init__(self,name,text,maxlength,pattern,default,required,accesskey,multiple)
    if size:
      self.size = size
    else:
      self.size = maxlength

  def inputfield(self,escape_html_chars='<>":={}()',label=0):
    return self.__label__(label)+self.inputfield_template % (
	'<input id="%s" name="%s" %s  maxlength="%d" size="%d" value="%s">' % (
	self.name,self.name,self.__accesskeyfield__(),self.maxlength,self.size,self.__defaultprint__()
      )
    )


class formHiddenInputClass(formInputClass):
  """
  <INPUT TYPE=HIDDEN>
  """

  def __init__(self,name,text,maxlength=0,pattern='',default='',required=0,accesskey='',multiple=0,show=0):
    formFieldClass.__init__(self,name,text,maxlength,pattern,default,required,accesskey,multiple)
    self.show = show

  def inputfield(self,escape_html_chars='<>":={}()',label=0):
    if self.show:
      default_str = self.__defaultprint__()
    else:
      default_str = ''
    return self.__label__(label)+self.inputfield_template % (
	'<input type=hidden id="%s" name="%s" %s  value="%s">%s' % (
	  self.name,self.name,self.__accesskeyfield__(),self.__defaultprint__(),default_str
      )
    )


class formPasswordClass(formFieldClass):
  """
  <INPUT TYPE=password>
  
  Mainly it's an own class because of own method contentprint()
  """

  def __init__(self,name,text,maxlength=0,pattern='',required=0,accesskey='',multiple=0,size=0):
    formFieldClass.__init__(self,name,text,maxlength,pattern,'',required)
    if size:
      self.size = size
    else:
      self.size = maxlength

  def inputfield(self,escape_html_chars='<>":={}()',label=0):
    return self.__label__(label)+self.inputfield_template % (
             '<input id="%s" name="%s" %s maxlength="%d" size="%d" type="password" value="">' % (
	       self.name,self.name,self.__accesskeyfield__(),self.maxlength,self.size
	     )
	   )

  def textprint(self):
    return len(self.content)*'*'

  def contentprint(self):
    return self.contentprint_template % (len(self.content)*'*')


class formSelectClass(formFieldClass):
  """
  <SELECT>
  """

  def __init__(self,name,text,options=[],default='',required=0,accesskey='',multiple=0,size=1,ignorecase=0,multiselect=0):

    if not (type(default) is types.ListType):
      default = [default]
    # pattern and maxlength are determined from __init__ params
    if options:
      maxlength = 0
      valuelist=[]
      for i in options:
        if type(i) is types.TupleType:
  	  valuelist.append(i[0])
          if len(i[0])>maxlength:
	    maxlength=len(i[0])
	else:
  	  valuelist.append(i)
          if len(i)>maxlength:
	    maxlength=len(i)
      pattern   = '^%s$' % string.join(map(re.escape,valuelist),'$|^')
    else:
      pattern   = ''
      maxlength = 0
    if multiple:
      multiple = len(options)
    if ignorecase:
      patternoptions = re.I
    else:
      patternoptions = 0
    formFieldClass.__init__(self,name,text,maxlength,(pattern,patternoptions),default,required,accesskey,multiple)
    self.options     = options
    self.size        = size
    self.multiselect = multiselect

  def inputfield(self,escape_html_chars='<>":={}()',label=0):
    s = ['<select id="%s" name="%s" %s  size="%d" %s>' % (
      self.name,self.name,self.__accesskeyfield__(),self.size," multiple"*(self.multiselect>0))]
    for i in self.options:
      if type(i) is types.TupleType:
        optionvalue = i[0]
	optiontext = i[1]
      else:
        optionvalue = optiontext = i
      if type(self.default) is types.ListType:
	optionselected = optionvalue in self.default
      else:
	optionselected = optionvalue == self.default
      s.append(
	'<option value="%s"%s>%s</option>' % (
	  charset.recode(charset.escapeHTML(optionvalue,escape_html_chars),self.charset,'html4'),
	  ' selected'*(optionselected),
	  charset.recode(charset.escapeHTML(optiontext,escape_html_chars),self.charset,'html4')
	)
      )
    s.append('</select>')
    return self.__label__(label)+self.inputfield_template % string.join(s,'\n')


class formRadioClass(formFieldClass):
  """
  <INPUT TYPE=RADIO>
  """

  def __init__(self,name,text,options='',default='',required=0,accesskey='',multiple=0):
    # pattern and maxlength are determined from __init__ params
    if len(options):
      pattern   = '(%s)' % string.join(map(re.escape,options),'|')
      maxlength = len(options[0])
      for i in options[1:]:
        if len(i)>maxlength:
	  maxlength=len(i)
    else:
      pattern   = ''
      maxlength = 0
    formFieldClass.__init__(self,name,text,maxlength,pattern,default,required,accesskey,multiple)
    self.options  = options

  def inputfield(self,escape_html_chars='<>":={}()',label=0):
    s = []
    for i in self.options:
      s.append('<input type="radio" id="%s" name="%s" %s value="%s"%s>%s<br>' % (
                  self.name,self.name,self.__accesskeyfield__(),i,' checked'*(i==self.default),i
		)
	      )
    return self.__label__(label)+self.inputfield_template % string.join(s,'\n')


class formCheckboxClass(formFieldClass):
  """
  <INPUT TYPE=CHECKBOX>
  """

  def __init__(self,name,text,value='',checked=0,required=0,accesskey='',multiple=0):
    pattern      = value
    maxlength    = len(value)
    formFieldClass.__init__(self,name,text,maxlength,pattern,'',required)
    self.value   = value
    self.checked = checked

  def inputfield(self,escape_html_chars='<>":={}()',label=0):
    return self.__label__(label)+self.inputfield_template % (
      '<input type="checkbox" id="%s" name="%s" %s value="%s"%s>' % (
        self.name,self.name,
	self.__accesskeyfield__(),
	self.value,' checked'*self.checked
      )
    )


class formKeygenClass(formFieldClass):
  """
  <KEYGEN>
  """
  def __init__(self,name,text,maxlength=0,required=0,accesskey='',multiple=0):
    formFieldClass.__init__(
      self,
      name,
      text,
      maxlength,
      (r'[ -z\r\n]*',re.M+re.S),
      required
    )

  def put(self,input):
    input = string.translate(input, string.maketrans("",""),"\r")
    input = string.translate(input, string.maketrans("",""),"\n")
    formFieldClass.put(self,input)

  def inputfield(self,challenge,label=0):
    return self.__label__(label)+self.inputfield_template % (
             '<keygen id="%s" name="%s" %s challenge="%s">' % (
               self.name,self.name,self.__accesskeyfield__(),challenge
	     )
	   )

  def contentprint(self):
    return self.contentprint_template % ('%d Bytes' % (len(self.content)))


class formException(Exception):
  """
  Base exception class to indicate form processing errors.
  """
  def __init__(self, *args):
      self.args = args


class formContentLengthException(formException):
  """
  Length of ALL input data too large.
  """
  def __init__(self,contentlength,maxcontentlength):
    formException.__init__(self,contentlength,maxcontentlength)
    self.contentlength = contentlength
    self.maxcontentlength = maxcontentlength
  def __str__(self):
    return 'Content length invalid. Expected at most %d bytes but received %d.\n' % (
      self.maxcontentlength,self.contentlength
    )


class formParamNameException(formException):
  """
  Parameter with unknown name attribute received.
  """
  def __init__(self,name):
    formException.__init__(self,name)
    self.name = name
  def __str__(self):
    return 'Unknown parameter %s.\n' % (self.name)


class formParamsMissing(formException):
  """
  Required parameters are missing.
  """
  def __init__(self,paramnamelist):
    formException.__init__(self,paramnamelist)
    self.missing = paramnamelist
  def __str__(self):
    return 'Required fields missing: %s\n' % (
      string.join(self.missing,', ')
    )


class formParamContentException(formException):
  """
  The user's input does not match the required format.
  """
  def __init__(self,name,text,content,reqregex):
    formException.__init__(self,name,text,content,reqregex)
    self.name     = name
    self.text     = text
    self.content  = content
    self.reqregex = reqregex
  def __str__(self):
    return 'Content of field %s does not match "%s". Input was: "%s"\n' % (
      self.text,self.reqregex,self.content
    )


class formParamStructException(formException):
  """
  Too many parameters with the same name attribute in user's input.
  """
  def __init__(self,name,count,maxfields):
    formException.__init__(self,name,count,maxfields)
    self.name      = name
    self.count     = count
    self.maxfields = maxfields
  def __str__(self):
    return 'Expected at most %d parameters for field %s, got %d.\n' % (
      self.maxfields,self.name,self.count
    )


class formParamLengthException(formException):
  """
  User's input for a certain parameter was too long.
  """
  def __init__(self,name,text,length,maxlength):
    formException.__init__(self,name,text,length,maxlength)
    self.name      = name
    self.text      = text
    self.length    = length
    self.maxlength = maxlength
  def __str__(self):
    return 'Content too long. Field %s has %d characters but is limited to %d.\n' % (
      self.text,self.length,self.maxlength
    )


class formClass:
  """
  Class for declaring and processing a whole <FORM>
  """

  def __init__(
    self,
    inf = None,		# Read from this file object
    env = os.environ,	# dictionary holding the environment vars
    charset = ''	# character set used when submitting the form
  ):
    # Dictionary der Eingabefelder-Objekte
    # {name:[FormFieldClass]}
    self.field            = {}
    # Dictionary mit Ordnungszaehler der Eingabefelder-Objekte
    # {name:len(field)}
    self.fieldcounter     = {}
    # Reihenfolgetreue Liste der vorgesehenen Eingabefelder-Namen
    self.keys             = []
    # Liste der tatsaechlich eingegebenen Eingabefelder-Namen
    self.inputkeys        = []
    # Skriptname

    self.env = env

    if inf:
      self.inf = inf
    else:
      self.inf = sys.stdin

    self.request_method = env['REQUEST_METHOD']
    self.server_name = env.get('SERVER_NAME',env.get('HTTP_HOST',''))
    self.server_port = env.get('SERVER_PORT','')
    self.script_name = env['SCRIPT_NAME']
    self.path_info = env.get('PATH_INFO','')
    self.query_string = env.get('QUERY_STRING','')
    self.http_user_agent = env.get('HTTP_USER_AGENT','')
    if charset:
      self.accept_charset = charset
    else:
      self.accept_charset = string.split(env.get('HTTP_ACCEPT_CHARSET','utf-8'),',')[0]

    if self.request_method=='POST':
      # Parameter von self.inf lesen
      self.contentlength = int(env['CONTENT_LENGTH'])
      self.query_string = self.inf.read(self.contentlength)
    elif self.request_method=='GET':
      self.query_string = env.get('QUERY_STRING','')
      self.contentlength = len(self.query_string)
    else:
      raise ValueError,"Invalid request method %s." % self.request_method

    self.maxcontentlength = 0


  def add(self,formfield):
    """
    Add a input field object to the form.
    """
    formfield.setcharset(self.accept_charset)
    if self.field.has_key(formfield.name):
      formfield.counter = self.fieldcounter[formfield.name]
      self.field[formfield.name].append(formfield)
      self.fieldcounter[formfield.name] = self.fieldcounter[formfield.name] + 1
    else:
      formfield.counter = 0
      self.field[formfield.name] = [formfield]
      self.keys.append(formfield.name)
      self.fieldcounter[formfield.name] = 1
    self.maxcontentlength = self.maxcontentlength + formfield.maxlength

  def getparams(
    self,
    ignoreemptyparams=0	# Ignore empty strings in user's input
  ):
    """
    Process user's input and store the values in the field objects.

    When a processing error occurs formException (or derivatives)
    are raised.
    """

    # Parse user's input
    inputlist = string.split(self.query_string,'&')

    # Any input present?
    if not len(inputlist):
      return

    datalength = 0
    # Zaehlerdict. mit Index paramname
    paramnumindex = {}

    # Loop over all name attributes declared
    for param in inputlist:

      if param:

        # Einzelne Parametername/-daten-Paare auseinandernehmen
        paramname,paramdata = string.split(param,'=',1)
	paramname = string.strip(urllib.unquote_plus(paramname))
	paramdata = string.strip(urllib.unquote_plus(paramdata))

        datalength = datalength+len(paramdata)

        # Gesamtlaenge der Daten noch zulaessig?
        if datalength > self.maxcontentlength:
          formContentLengthException(datalength,self.maxcontentlength)

        # Unbekannter Parametername angegeben?
	if not (paramname in self.keys):
          raise formParamNameException(paramname)

        if paramnumindex.has_key(paramname):
	  paramnumindex[paramname] = paramnumindex[paramname] + 1
	else:
	  paramnumindex[paramname] = 0

        # Anzahl der Parameter gleichen Namens noch zulaessig?
	if paramnumindex[paramname] >= len(self.field[paramname]):
          if (self.field[paramname][0].multiple):
  	    paramnumindex[paramname] = 0
          else:
            raise formParamStructException(paramname,paramnumindex[paramname]+1,len(self.field[paramname]))

        field = self.field[paramname][paramnumindex[paramname]]

        # input is empty string?
	if paramdata:
          # Zusaetzlich pruefen
          # Laenge gueltig?
          if len(paramdata) > field.maxlength:
            raise formParamLengthException(field.name,field.text,len(paramdata),field.maxlength)
          rm = field.regex.match(paramdata)
          if rm==None or rm.group(0)!=paramdata:
            raise formParamContentException(field.name,field.text,paramdata,field.regex.pattern)
	  # Eingabe ist gueltig und wird in content uebernommen
          if not paramname in self.inputkeys:
	    self.inputkeys.append(paramname)
        else:
          if (not ignoreemptyparams) and (not paramname in self.inputkeys):
	    self.inputkeys.append(paramname)

        # Store user's input in form field object
        field.put(paramdata)

    # Are all required parameters present?
    missing_params = []
    for param in self.keys:
      for i in self.field[param]:
	if i.required and not (param in self.inputkeys):
	  missing_params.append((i.name,i.text))
    if missing_params:
      raise formParamsMissing(missing_params)

    return
