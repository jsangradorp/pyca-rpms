import string

# IP-Adresse in Stringform zu 4er-Tupel konvertieren
def ipadrstr2tuple(IPAdrStr=''):
  return map(string.atoi,string.split(IPAdrStr,'.',3))

# IP-Adresse mit Netzwerkadresse/Netzwerkmaske vergleichen
def MatchIPAdr(IPAdress,NetworkAdress,Mask):
  IPAdressT=ipadrstr2tuple(IPAdress)
  MaskT=ipadrstr2tuple(Mask)
  NetworkAdressT=ipadrstr2tuple(NetworkAdress)
  return (IPAdressT[0]&MaskT[0] == NetworkAdressT[0]&MaskT[0]) and \
	 (IPAdressT[1]&MaskT[1] == NetworkAdressT[1]&MaskT[1]) and \
	 (IPAdressT[2]&MaskT[2] == NetworkAdressT[2]&MaskT[2]) and \
	 (IPAdressT[3]&MaskT[3] == NetworkAdressT[3]&MaskT[3])

def MatchIPAdrList(IPAdr,subnetlist):
  if IPAdr and subnetlist:
    for subnet in subnetlist:
      net, mask = string.split(subnet,'/',1)
      if MatchIPAdr(IPAdr,net,mask):
        return 1
  return 0

