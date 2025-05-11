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
	printf("[DEBUG] loading firewall configuration\n");
	FirewallConfig config = load_config("firewall.conf");

	
	// initial Bloom filter 
	printf("[DEBUG] Initial blacklist\n");
	init_blacklist(config.blacklist_file);
	
	// set Netfilter queus
	printf("[DEBUG] Open netfilter queue\n");
	h = nfq_open(); // init connecteion with Netfilter
	if(!h){
		perror("nfq_open fail");
		exit(1);
	}

	nfq_unbind_pf(h, AF_INET);
	nfq_bind_pf(h, AF_INET);
	
	printf("[DEBUG] creating netfilter queue\n");
	qh = nfq_create_queue(h, config.queue_num, &process_packet, NULL);
	if(!qh){
		perror("[ERROR] nfq_create_queue failed\n");
		exit(1);
	} else{
		printf("[DEBUG] Queue created successfully\n");
	}

	nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff); // copy everything 
	
	int fd = nfq_fd(h); // listen for incoming data
	char buf[4096] __attribute__((aligned));
	int rv;
	
	printf("[*] Firewall is running on queue %d...\n", config.queue_num);
	printf("[DEBUG] Waiting for packets...\n");
	while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
		if (rv == 0) {
			printf("[DEBUG] No packets received.\n");
		} else {
			printf("[DEBUG] Received packet of size %d\n", rv);
		}
		nfq_handle_packet(h, buf, rv);
	}

	
	
	cleanup();
	return 0;
}

