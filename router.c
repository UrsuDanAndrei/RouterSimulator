#include "skel.h"
#include "main_headers.h"
#include "arp.h"
#include "queue.h"
#include "routing_table.h"

/* returneaza 1 daca dmac-ul corespunde interfetei intf_id, 0 altfel */
int same_mac(int intf_id, uint8_t* dmac) {
	uint8_t* intf_mac = NULL;
	get_interface_mac(intf_id, intf_mac);

	// sizezof !!!
	return !memcmp(intf_mac, dmac, MAC_SIZE * sizeof(uint8_t));
}

arp_entry* get_arp_entry(arp_entries* arp_table, __u32 ip) {
	for (int i = 0; i < arp_table->len; ++i) {
        if (arp_table->entries[i].ip == ip) {
            return &arp_table->entries[i];
        }
    }

    return NULL;
}

// void layer_3_basic_setup(struct iphdr* ip_hdr, __u32 ips, __u32 ipd) {
// 	ip_hdr->version = 4;
// 	ip_hdr->
// }

void packet_for_router_intf(arp_entries* arp_table, int intf_id,
												packet* pkt, queue wait_list) {
	uint8_t* intf_mac = NULL;
	get_interface_mac(intf_id, intf_mac);

	struct ether_header *eth_hdr = (struct ether_header *) pkt->payload;
	struct iphdr *ip_hdr = (struct iphdr *) (pkt->payload + IP_OFFSET);

	if (ip_hdr->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmp_hdr = (struct icmphdr *) (pkt->payload
																+ ICMP_OFFSET);

		// !!! nu stiu daca trebuie acest if
		// discard-uieste pachetul daca nu este icmp echo request
		// if (icmp_hdr->type != ICMP_ECHO || icmp_hdr->code != 0) {
		// 	return;
		// }

		// daca este un icmp echo request se raspunde cu un icmp echo reply
		packet* reply = (packet*) malloc(sizeof(packet));

		// layer 3 setup
		struct iphdr *ip_hdr_reply = (struct iphdr*) (reply->payload
																+ IP_OFFSET);
		// !!! se poate sa trebuiasca adaugate mai multe campuri
		ip_hdr_reply->version = 4;
		ip_hdr_reply->ttl = 64;
		ip_hdr_reply->protocol = IPPROTO_ICMP;

		ip_hdr_reply->saddr = inet_addr(get_interface_ip(intf_id));
		ip_hdr_reply->daddr = ip_hdr->saddr;

		// !!! se poate sa fie necesar sa faci si header-ul pt icmp
		
		// layer 2 setup
		// !!! vezi ca trebuie sa cautiin tabela de rutare inainte sa dai arp request!!!
		// cauta in tabela de rutare calea catre urmatorul hop

		// !!! sizeof
		memcpy(eth_hdr->ether_shost, intf_mac, MAC_SIZE * sizeof(uint8_t));
		// !!! htons aici pui ARP
		eth_hdr->ether_type = htons(ETHERTYPE_IP);
		arp_entry* pair_ip_mac = get_arp_entry(arp_table, ip_hdr->daddr);

		if (!pair_ip_mac) {
			// daca nu s-a gasit nicio intrare se trimite un arp request
			packet arp_request;
			ip_hdr_reply->version = 4;
			ip_hdr_reply->ttl = 64;
			// !!! nu aici, ci in ether_type din ether_headr
			//ip_hdr_reply->protocol = ARP_CODE;


			// se pune pachetul in coada
			queue_enq(wait_list, reply);
		}
	}
}

int cmp_route(const void* a, const void* b) {
	rt_entry* entry1 = (rt_entry*) a;
	rt_entry* entry2 = (rt_entry*) b;
	// compara la nivel de string-uri
	if (entry1->mask == entry2->mask) {
		if (1LL * entry1->network < 1LL * entry2->network) {
			return -1;
		}

		return 1;
	} else if (1LL * entry1->mask < 1LL * entry2->mask) {
		return -1;
	} else {
		return 1;
	}
}

void parse_routing_table(rt_entries* rt_table) {
	FILE *in;
	in = fopen("rtable.txt", "r");

	int i = 0;
	char line[MAX_ROUTING_ENTRTY_SIZE];

	while (fgets(line, sizeof(line), in) != NULL) {
		// ignora '\n'
		line[strlen(line) - 1] = '\0';

		// separa informatia utila
		char* info = strtok(line, " ");
		rt_table->entries[i].network = inet_addr(info);

		info = strtok(NULL, " ");
		rt_table->entries[i].next_hop = inet_addr(info);

		info = strtok(NULL, " ");
		rt_table->entries[i].mask = inet_addr(info);

		info = strtok(NULL, " ");
		rt_table->entries[i].intf = atoi(info);
		
		++i;
	}
	
	rt_table->len = i;

	// !!! se sorteaza cu adresa de la dreapta la stanga for some reason
	// !!! daca sortarea e ca si cautarea ar trebui sa fie ok

	qsort(rt_table->entries, rt_table->len, sizeof(rt_entry), cmp_route);

	for (int j = 0; j < rt_table->len; ++j) {
		struct in_addr help;
    	help.s_addr = rt_table->entries[j].mask;

		printf("%s ", inet_ntoa(help));

		help.s_addr = rt_table->entries[j].network;
		printf("%s ", inet_ntoa(help));

		help.s_addr = rt_table->entries[j].next_hop;
		printf("%s ", inet_ntoa(help));

		printf("%d\n", rt_table->entries[j].intf);
	}
}

int main(int argc, char *argv[])
{

	packet pkt;
	int rc;

	init();
	//return 0;
	// printf("ceva\n");
	// fflush(stdout);
	// //return 0;

	// // --------------------------------
	// rt_entries rt_table;
	// parse_routing_table(&rt_table);
	// return 0;

	// // ------------------------------

	// arp_entries arp_table;
	// queue wait_list = queue_create();

	while (1) {
        // primeste un pachet de la o interfata
		rc = get_packet(&pkt);
		DIE(rc < 0, "get_message");

        // struct ether_header *eth_hdr = (struct ether_header *) pkt.payload;
		// struct iphdr *ip_hdr = (struct iphdr *) (pkt.payload + IP_OFFSET);

        // // verifica daca pachetul este adresat unei interfete proprii
		// for (int i = 0; i < ROUTER_NUM_INTERFACES; ++i) {
		// 	if (same_mac(i, eth_hdr->ether_dhost)) {
		// 		packet_for_router_intf(&arp_table, i, &pkt, wait_list);
		// 		continue;
		// 	}
		// } 
	}
}
