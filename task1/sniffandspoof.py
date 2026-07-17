#!/usr/bin/env python3

from scapy.all import *

def spoof(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load if Raw in pkt else b''
        
        spoofed_pkt = ip/icmp/data
        
        send(spoofed_pkt)

        print("Spoofed reply sent:")
        spoofed_pkt.show()

pkt = sniff(filter='icmp', prn=spoof)
