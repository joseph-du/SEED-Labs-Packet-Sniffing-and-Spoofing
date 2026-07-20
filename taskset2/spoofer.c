#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <linux/icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// Checksum function for IP and ICMP
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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <source IP> <destination IP>\n", argv[0]);
        exit(-1);
    }

    char *src_ip = argv[1];
    char *dst_ip = argv[2];

    int sd;
    struct sockaddr_in sin;
    char buffer[1024];

    // Create raw socket
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("socket() error");
        exit(-1);
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(dst_ip);

    // Construct IP header
    struct ip *iph = (struct ip *)buffer;
    iph->ip_hl = 5;  // Header length
    iph->ip_v = 4;   // Version
    iph->ip_tos = 0; // Type of service
    iph->ip_len = sizeof(struct ip) + sizeof(struct icmphdr); // Total length
    iph->ip_id = htonl(54321); // ID
    iph->ip_off = 0; // Fragment offset
    iph->ip_ttl = 255; // Time to live
    iph->ip_p = IPPROTO_ICMP; // Protocol
    iph->ip_sum = 0; // Checksum (set later)
    iph->ip_src.s_addr = inet_addr(src_ip); // Spoofed source
    iph->ip_dst.s_addr = inet_addr(dst_ip); // Destination

    // Calculate IP checksum
    iph->ip_sum = checksum((unsigned short *)buffer, sizeof(struct ip));

    // Construct ICMP header
    struct icmphdr *icmph = (struct icmphdr *)(buffer + sizeof(struct ip));
    icmph->type = ICMP_ECHO; // Echo request
    icmph->code = 0;
    icmph->un.echo.id = 1234; // ID
    icmph->un.echo.sequence = 1;   // Sequence
    icmph->checksum = 0; // Checksum (set later)

    // ICMP data (optional)
    strcpy((char *)icmph + sizeof(struct icmphdr), "Hello from spoofer");

    // Update IP length
    iph->ip_len = sizeof(struct ip) + sizeof(struct icmphdr) + strlen("Hello from spoofer");

    // Recalculate IP checksum
    iph->ip_sum = 0;
    iph->ip_sum = checksum((unsigned short *)buffer, sizeof(struct ip));

    // Calculate ICMP checksum
    icmph->checksum = checksum((unsigned short *)icmph, sizeof(struct icmphdr) + strlen("Hello from spoofer"));

    // Send the packet
    int ip_len = iph->ip_len;
    if (sendto(sd, buffer, ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() error");
        exit(-1);
    }

    printf("Spoofed ICMP echo request sent from %s to %s\n", src_ip, dst_ip);

    close(sd);
    return 0;
}