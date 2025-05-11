// Processes each packet and checks if it should be dropped or accepted.
#include "packet_filter.h"
#include "blacklist.h"
#include <netinet/ip.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h> 
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>  // for IP header
#include <netinet/tcp.h> // for TCP header
#include <netinet/udp.h> // for UDP header
#include <netinet/ip_icmp.h> // for ICMP header

// Function to identify the protocol
void inspect_packet(char *packet_data) {
    // Cast the packet data to the IP header structure
    struct ip *ip_header = (struct ip *) packet_data;
    
    // Identify the protocol
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            printf("TCP Packet\n");
            break;
        case IPPROTO_UDP:
            printf("UDP Packet\n");
            break;
        case IPPROTO_ICMP:
            printf("ICMP Packet\n");
            break;
        default:
            printf("Unknown Protocol\n");
            break;
    }
}

// Function to extract and display ports for TCP and UDP packets
void extract_ports(char *packet_data) {
    struct ip *ip_header = (struct ip *) packet_data;

    // If it's a TCP or UDP packet, extract the ports
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)((char *)ip_header + (ip_header->ip_hl << 2));
        printf("TCP Source Port: %u, Dest Port: %u\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)((char *)ip_header + (ip_header->ip_hl << 2));
        printf("UDP Source Port: %u, Dest Port: %u\n", ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
    }
}


// read from net tool to get packet, 
int process_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                   struct nfq_data *nfa, void *data){
					   
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ntohl(ph->packet_id);
    unsigned char *packetData;
    int len = nfq_get_payload(nfa, &packetData);

    if (len >= sizeof(struct iphdr)) {
        struct iphdr *ip = (struct iphdr *)packetData;
        struct in_addr src_addr;
        src_addr.s_addr = ip->saddr;

        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));

        inspect_packet((char *) packetData);

        // call 
        extract_ports((char *)packetData);

        if (is_blacklisted(src_ip)) {
            printf("[DROP] %s\n", src_ip);
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        } else {
            printf("[ACCEPT] %s\n", src_ip);
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}
