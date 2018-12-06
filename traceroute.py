from scapy.all import *
a = IP()
a.dst = '1.2.3.4'
a.ttl = 1
b = ICMP()
send(a/b)

