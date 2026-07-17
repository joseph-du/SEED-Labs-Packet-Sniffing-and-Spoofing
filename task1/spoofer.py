#!/usr/bin/env python3

from scapy.all import *

a = IP()
a.dst = '1.1.1.1'
a.src = '10.0.2.15'
b = ICMP()
p = a/b
send(p)
