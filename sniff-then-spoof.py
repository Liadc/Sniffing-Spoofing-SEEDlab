from scapy.all import *

def print_pkt(pkt):
	a = IP(dst=pkt[IP].src)
	a.src = pkt[IP].dst
	a.id = 0
	a.ttl = 200
	a.tos = 0xb8
	b = pkt[ICMP]
	b.chksum = pkt[ICMP].chksum+0x0800
	b.type = 'echo-reply'
	p = a/b
	send(p)

pkt = sniff(filter='icmp and not src host 123.123.232.111',prn=print_pkt)



