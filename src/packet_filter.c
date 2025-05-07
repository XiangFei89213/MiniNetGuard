#include "packet_filter.h"
#include "blacklist.h"
#include <netinet/ip.h>
#include <libnetfilter_queue/libnetfilter_queue_h>
#include <arpa/inet.h> 

// read from net tool to get packet, 
int process_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                   struct nfq_data *nfa, void *data){
					   
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    u32 id = ntohl(ph->packet_id);
    unsigned char *packetData;
    int len = nfq_get_payload(nfa, &packetData);

    if (len >= sizeof(struct iphdr)) {
        struct iphdr *ip = (struct iphdr *)packetData;
        struct in_addr src_addr;
        src_addr.s_addr = ip->saddr;

        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));

        if (is_blacklisted(src_ip)) {
            printf("[DROP] %s\n", src_ip);
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        } else {
            printf("[ACCEPT] %s\n", src_ip);
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}
