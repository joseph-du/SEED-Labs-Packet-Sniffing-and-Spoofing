#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <linux/icmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// Checksum function
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Function to send spoofed ICMP echo reply
void send_spoofed_reply(struct ip *orig_iph, struct icmphdr *orig_icmph, int payload_len) {
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("socket() error");
        return;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = orig_iph->ip_src.s_addr;  // Reply to original source

    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    // Construct IP header for reply
    struct ip *iph = (struct ip *)buffer;
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct icmphdr) + payload_len;
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_ICMP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = orig_iph->ip_dst.s_addr;  // Spoof as original dest
    iph->ip_dst.s_addr = orig_iph->ip_src.s_addr;  // To original source

    iph->ip_sum = checksum((unsigned short *)buffer, sizeof(struct ip));

    // Construct ICMP reply
    struct icmphdr *icmph = (struct icmphdr *)(buffer + sizeof(struct ip));
    icmph->type = 0;  // Echo reply
    icmph->code = 0;
    icmph->un.echo.id = orig_icmph->un.echo.id;
    icmph->un.echo.sequence = orig_icmph->un.echo.sequence;
    icmph->checksum = 0;

    // Copy payload
    char *orig_payload = (char *)orig_icmph + sizeof(struct icmphdr);
    char *payload = (char *)icmph + sizeof(struct icmphdr);
    memcpy(payload, orig_payload, payload_len);

    // Calculate ICMP checksum
    icmph->checksum = checksum((unsigned short *)icmph, sizeof(struct icmphdr) + payload_len);

    // Send
    if (sendto(sd, buffer, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() error");
    } else {
        printf("Spoofed echo reply sent to %s\n", inet_ntoa(sin.sin_addr));
    }

    close(sd);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Parse Ethernet
    struct ether_header *eth = (struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    // Parse IP
    struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    if (iph->ip_p != IPPROTO_ICMP) return;

    // Parse ICMP
    struct icmphdr *icmph = (struct icmphdr *)((u_char *)iph + (iph->ip_hl << 2));
    if (icmph->type != 8 || icmph->code != 0) return;  // Not echo request

    printf("Intercepted ICMP echo request from %s to %s\n", inet_ntoa(iph->ip_src), inet_ntoa(iph->ip_dst));

    // Calculate payload length
    int ip_len = ntohs(iph->ip_len);
    int icmp_len = ip_len - (iph->ip_hl << 2);
    int payload_len = icmp_len - sizeof(struct icmphdr);

    // Send spoofed reply
    send_spoofed_reply(iph, icmph, payload_len);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net, mask;
    char *dev = "br-5b4dee0acfb1";

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask: %s\n", errbuf);
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    pcap_compile(handle, &fp, filter_exp, 0, mask);
    pcap_setfilter(handle, &fp);

    printf("Sniff-and-spoof program running on %s...\n", dev);
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}