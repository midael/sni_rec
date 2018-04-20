## pip install {scapy|scapy-ssl_tls}
import sys
from scapy.all import *
from scapy.layers.ssl_tls import *


## Set Interface to sniff from
interface="enp0s3"

def pkt_callback(pkt):
  if pkt.haslayer(SSL):
    try:
      if pkt[SSL].records[0].content_type == 22:
        if pkt[SSL].records[0].handshakes[0].type == 1: 
          ##pkt.show2()
          for i in pkt[SSL].records[0].handshakes[0].extensions:
            if i.type == 0:
              for j in i.server_names:
                print j.data + ";" + str(pkt[IP].src) + ";" + \
                      str(pkt[TCP].sport) + ";" + str(pkt[IP].dst) + ";" + \
                      str(pkt[TCP].dport)
    except:
      print "+"
      ##pkt.show2()      
      pass                      

try:
  bind_layers(TCP, SSL)
  ##bind_layers(UDP, SSL)
  sniff(iface=interface, prn=pkt_callback, store=0)
except:
  print "Error: got r00t? Right interface?"
  sys.exit(1)


