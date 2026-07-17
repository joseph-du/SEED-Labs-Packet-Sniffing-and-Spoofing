#!/usr/bin/env python3

from scapy.all import *

def print_pkt(pkt):
    pkt.show()

# Task 1.1B Part 1: pkt = sniff(iface=['br-f184ab6f6030', 'enp0s3'] filter='icmp', prn=print_pkt)
# Task 1.1B Part 2: pkt = sniff(iface=['br-f184ab6f6030', 'enp0s3'] filter='tcp and src 10.9.0.1 and dst port 23', prn=print_pkt)
# Task 1.1B Part 3: pkt = sniff(iface=['br-f184ab6f6030', 'enp0s3'] filter='net 128.230.0.0/16', prn=print_pkt)
