#include <stdio.h>
#include <stdlib.h>
#include <signal.h> // control+C
#include <libnetfilter_queue/libnetfilter_queue.h> // hook to Netfiler 

#include "config_parser.h"
#include "blacklist.h"
#include "packet_filter.h"

static struct nfq_handle *h;
static struct nfq_q_handle *qh;

void cleanup() {
	printf("\n[!] Cleaning up\n");
	nfq_destroy_queue(qh);
	nfq_close(h);
	system("sudo iptables -F");
	exit(0);
}

int main(int argc, char **argv){
	signal(SIGINT, cleanup); // got ctrl+c
	
	// 1. read config file
	FirewallConfig config = load_config(firewall.conf);

	
	// initial Bloom filter 
	init_blacklist(config.blacklist_file);
	
	// set Netfilter queus
	h = nfq_open(); // init connecteion with Netfilter
	if(!h){
		perror("nfq_open");
		exit(1);
	}

	nfq_unbind_pf(h, AF_INET);
	nfq_bind_pf(h, AF_INET);
	
	qh = nfq_create_queue(h, config.queue_num, &process_packet, NULL);
	nft_set_mode(qh, NFQNL_COPY_PACKET, 0xffff); // copy everything 
	
	int fd = nfq_fd(h); // listen for incoming data
	char buf[4096] __attribute__((aligned));
	int rv;
	
	printf("[*] Firewall is running on queue %d...\n", config.queue_num);
	while((rv == recv(fd, buf, sizeof(buf), 0)) >= 0){ // when receive packet, 
		nfq_handle_packet(h, buf, rv);
	}
	
	
	cleanup();
	return 0;
}

