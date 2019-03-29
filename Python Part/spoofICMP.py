from scapy.all import *

a = IP() 
a.dst = '192.168.43.35' #another machine IP in our network. we will run wireshark on this machine to capture the spoofed packet.
a.src = '1.3.3.7' #we are spoofing the source ip!!!
b = ICMP()
p = a/b
send(p)
