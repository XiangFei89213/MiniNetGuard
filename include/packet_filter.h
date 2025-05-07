#ifndef PACKET_FILTER_H
#define PACKET_FILTER_H

#include <libnetfilter_queue/libnetfilter_queue.h>

int process_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                   struct nfq_data *nfa, void *data);

#endif
