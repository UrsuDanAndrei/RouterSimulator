#include "skel.h"
#include "main_headers.h"
#include "arp.h"

/* returneaza 1 daca dmac-ul corespunde interfetei intf_id, 0 altfel */
int same_mac(int intf_id, uint8_t* dmac) {
	uint8_t* intf_mac;
	get_interface_mac(intf_id, intf_mac);

	return !memcmp(intf_mac, dmac, sizeof(intf_mac));
}

struct arp_entry* get_arp_entry(struct arp_table_entries* arp_table, __u32 ip) {
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

void packet_for_router_intf(arp_table_entries* arp_table, int intf_id,
																packet* pkt) {
	uint8_t* intf_mac;
	get_interface_mac(intf_id, intf_mac);

	struct ether_header *eth_hdr = (struct ether_header *) pkt->payload;
	struct iphdr *ip_hdr = (struct iphdr *) (pkt->payload + IP_OFFSET);

	if (ip_hdr->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmp_hdr = (struct icmphdr *) (pkt->payload
																+ ICMP_OFFSET);

		// !!!
		// discard-uieste pachetul daca nu este icmp echo request
		// if (icmp_hdr->type != ICMP_ECHO || icmp_hdr->code != 0) {
		// 	return;
		// }

		// daca este un icmp echo request raspunde cu un icmp echo reply
		packet* reply = (packet*) malloc(sizeof(packet));

		// layer 3 setup
		struct iphdr *ip_hdr_reply = (struct iphdr*) (reply->payload
																+ IP_OFFSET);
		ip_hdr_reply->version = 4;
		ip_hdr_reply->ttl = 64;
		ip_hdr_reply->protocol = IPPROTO_ICMP;
		ip_hdr_reply->saddr = get_interface_ip(intf_id);

		// !!! se poate sa fie necesar sa faci si header-ul pt icmp
		


		// layer 2 setup
		memcpy(eth_hdr->ether_shost, intf_mac, sizeof(intf_mac));
		struct arp_entry* pair_ip_mac = get_arp_entry(arp_table, ip_hdr->daddr);
		if (!pair_ip_mac) {
			// add to wait_queue
		}

	}
}

// int cmp_route(const struct arp_entry* entry1, const struct arp_entry* entry2) {
// 	return entry1->ip - entry2->ip;
// }


int main(int argc, char *argv[])
{
	packet pkt;
	int rc;

	init();
	struct arp_table_entries arp_table;

	while (1) {
        // primeste un pachet de la o interfata
		rc = get_packet(&pkt);
		DIE(rc < 0, "get_message");

        struct ether_header *eth_hdr = (struct ether_header *) pkt.payload;
		struct iphdr *ip_hdr = (struct iphdr *) (pkt.payload + IP_OFFSET);

        // verifica daca pachetul este adresat unei interfete proprii
		for (int i = 0; i < ROUTER_NUM_INTERFACES; ++i) {
			if (same_mac(i, eth_hdr->ether_dhost)) {
				packet_for_router_intf(&arp_table, i, &pkt);
				continue;
			}
		} 
	}
}
