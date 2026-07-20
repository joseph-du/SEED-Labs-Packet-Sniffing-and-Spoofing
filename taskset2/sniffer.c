#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <ctype.h>

/* 
    This function will be invoked by pcap for each captured packet.
    We can process each packet inside the function.
    To compile: gcc -o sniff packetsniffer.c -lpcap
*/

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Got a packet\n");

    // Parse Ethernet header
    struct ether_header *eth = (struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;  // Not an IP packet
    }

    // Parse IP header
    struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));
    if (ip->ip_p != IPPROTO_TCP) {
        return;  // Not a TCP packet
    }

    // Parse TCP header
    struct tcphdr *tcp = (struct tcphdr *)((u_char *)ip + (ip->ip_hl << 2));
    int tcp_header_len = tcp->th_off << 2;

    // Calculate payload
    u_char *payload = (u_char *)tcp + tcp_header_len;
    int ip_total_len = ntohs(ip->ip_len);
    int payload_len = ip_total_len - (ip->ip_hl << 2) - tcp_header_len;

    if (payload_len > 0) {
        printf("TCP Payload (%d bytes): ", payload_len);
        for (int i = 0; i < payload_len; i++) {
            if (isprint(payload[i])) {
                printf("%c", payload[i]);
            } else {
                printf("\\x%02x", payload[i]);
            }
        }
        printf("\n");
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    /*
        task2.1b
        filter: icmp and host 10.9.0.5 and host 10.9.0.6
        filter: tcp dst portrange 10-100
    */
    char filter_exp[] = "tcp port 23";
    bpf_u_int32 net, mask;
    char *dev = "br-5b4dee0acfb1";

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    
    /*
        Step 1: Open live pcap session on NIC with name eth3.
        Students need to change "eth3" to the name found on their own
        machines (using ifconfig). The interface to the 10.9.0.0/24
        network has a prefix "br-" (if the container setup is used).
    */

    // changing the third argument from 0 to 1 sets promiscuous mode
    handle = pcap_open_live("br-5b4dee0acfb1", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }
    
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, mask);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}