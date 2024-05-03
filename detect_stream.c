#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip_icmp.h>

#define MY_IP "192.168.0.0"

// Function to calculate checksum
unsigned short checksum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void send_packet(src_ip, src_port, dest_ip, dest_port, syn) {
    // Fill in the IP header
    struct iphdr ip_header;
    ip_header.ihl = 5;
    ip_header.version = 4;
    ip_header.tos = 0;
    ip_header.tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip_header.id = htons(54321);
    ip_header.frag_off = 0;
    ip_header.ttl = 255;
    ip_header.protocol = IPPROTO_TCP;
    ip_header.check = 0; // Set to 0 for now
    ip_header.saddr = inet_addr(src_ip);
    ip_header.daddr = inet_addr(dest_ip);

    // Fill in the TCP header
    struct tcphdr tcp_header;
    tcp_header.source = htons(src_port);
    tcp_header.dest = htons(dest_port);
    tcp_header.seq = 0;
    tcp_header.ack_seq = 0;
    tcp_header.doff = 5; // Data offset
    tcp_header.fin = 0;
    tcp_header.syn = syn ? 1 : 0; // SYN flag
    tcp_header.rst = 0;
    tcp_header.psh = 0;
    tcp_header.ack = 0;
    tcp_header.urg = 0;
    tcp_header.window = htons(5840); // Maximum allowed window size
    tcp_header.check = 0; // Set to 0 for now
    tcp_header.urg_ptr = 0;

    // Calculate IP checksum
    ip_header.check = checksum((unsigned short *)&ip_header, sizeof(struct iphdr) / 2);

    // Calculate TCP checksum
    char *packet = (char *)malloc(ip_header.tot_len);
    memcpy(packet, &ip_header, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));
    tcp_header.check = checksum((unsigned short *)packet, sizeof(struct iphdr) + sizeof(struct tcphdr));
    memcpy(packet + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));
}

int main( int argc, char* argv[] ) {
    if (argc != 5) {
        exit(1);
    }
    char* server_public_ip = argv[1];
    char* router_public_ip = argv[1];
    int port_range_min = atoi(argv[3]);
    int port_range_max = atoi(argv[4]);

    for (int port = port_range_min; port <= port_range_max; port++) {
        // Send packet to test connection initialization
        send_packet(MY_IP, port, server_public_ip, server_port, true);
        // Spoof SYN/ACK
        send_packet(server_public_ip, server_port, router_public_ip, port, true);
    }
}

int main() {

}