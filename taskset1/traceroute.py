#!/usr/bin/env python3

from scapy.all import *

a = IP()
a.dst = '130.160.24.175'
a.ttl = 1
b = ICMP()
p = a/b
send(p)
