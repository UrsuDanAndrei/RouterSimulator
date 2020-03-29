#include "skel.h"
#include "main_headers.h"

// returneaza 1 daca dmac-ul corespunde interfetei intf_id, 0 altfel
int coresponding_mac(int intf_id, uint8_t* dmac) {
	uint8_t* intf_mac = (uint8_t*) malloc(6 * sizeof(uint8_t));
	get_interface_mac(intf_id, intf_mac);
	
	if (memcmp(intf_mac, dmac, ETH_ALEN * sizeof(uint8_t)) == 0) {
		return 1;
	}

	return 0;
}

// !!! daca vine un pachet cu ip pt interfata dar nu are mac-ul ei
// !!! ai grija la modul cum aloca get_ip_interface si
// get_mac_interface
// !!! poate faci free la unele pachete trimise
// !!! poate adaugi void add_arp_entry


// !!!!!!!!!!!1 rt_table lucreaza cu tot in little endian !!!
// arp_table lucreaza cu tot in big endian !!!!!!!!!!!!!!!!!!!!!!!!!!!11


// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! TOT CE VINE DE LA GET_BEST_ROUTE TREBUIE SCHIMBAT ENDIAN-UL

void packet_for_router_intf(arp_entries* arp_table, int intf_id,
						   packet* pkt, queue wait_list, rt_entries* rt_table) {
	
	struct ether_header *eth_hdr = (struct ether_header *) pkt->payload;

	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
		arp_hdr *arphdr = (arp_hdr *) (pkt->payload
												+ sizeof(struct ether_header));
		// verific daca este un arp request sau un arp reply
		if (ntohs(arphdr->ar_op) == 1) {
			// am primit un arp request, raspund cu un arp reply
		// !!! poti faci si free aici pt copy
			// arp ip part setup
			uint8_t* copy = (uint8_t*) malloc(4 * sizeof(uint8_t));
			memcpy(copy, arphdr->sip_addr, 4 * sizeof(uint8_t));
			memcpy(arphdr->sip_addr, arphdr->dip_addr, 4 * sizeof(uint8_t));;
			memcpy(arphdr->dip_addr, copy, 4 * sizeof(char));

			// arp ethernet part setup
			memcpy(arphdr->dhw_addr, arphdr->shw_addr, 6 * sizeof(char));
			get_interface_mac(intf_id, arphdr->shw_addr);
			arphdr->ar_op = htons(2);

			// ethernet header setup
			memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6 * sizeof(uint8_t));
			get_interface_mac(intf_id, eth_hdr->ether_shost);
			eth_hdr->ether_type = htons(ETHERTYPE_ARP);
			send_packet(pkt->interface, pkt);
			free(pkt);
		} else {
			// adaug intrarea in tabela arp
			arp_entry *reply_entry = (arp_entry *) malloc(sizeof(reply_entry));
			memcpy(&reply_entry->ip, arphdr->sip_addr, 4 * sizeof(uint8_t));
			memcpy(reply_entry->mac, arphdr->shw_addr, 6 * sizeof(uint8_t));
			update_arp_table(arp_table, reply_entry);

			// verific daca pot pleca pachete acum
			queue copy;
			copy = queue_create();

			while (!queue_empty(wait_list)) {
				packet* waiting_pkt = queue_deq(wait_list);

				struct ether_header* eth_hdr_waiting_pkt = (struct ether_header*) waiting_pkt->payload;
				struct iphdr *ip_hdr_waiting_pkt = (struct iphdr *) (waiting_pkt->payload + IP_OFFSET);

				arp_entry* ip2mac = get_arp_entry(arp_table, ip_hdr_waiting_pkt->daddr);

				if (ip2mac != NULL) {
					memcpy(eth_hdr_waiting_pkt->ether_dhost, ip2mac->mac, 6 * sizeof(uint8_t));
					send_packet(waiting_pkt->interface, waiting_pkt);
					free(pkt);
				} else {
					queue_enq(copy, waiting_pkt);
				}
			}

			while (!queue_empty(copy)) {
				queue_enq(wait_list, queue_deq(copy));
			}

			free(copy);
		}
	} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
		struct iphdr *ip_hdr = (struct iphdr *) (pkt->payload + IP_OFFSET);

		// discard-uieste pachetul daca nu este icmp echo request (nu se specifica in cerinta alte pachete ip la care router-ul trebuie sa raspunda)
		// sau pe care ar trebui sa le proceseze
		if (ip_hdr->protocol == 1) {
			struct icmphdr *icmp_hdr = (struct icmphdr *) (pkt->payload
																	+ ICMP_OFFSET);
			if (!(icmp_hdr->type == 8 && icmp_hdr->code == 0)) {
				return;
			}

			send_icmp_packet(arp_table, intf_id, ip_hdr->saddr, wait_list, rt_table, 0, 0, pkt);
		} else {
			free(pkt);
		}
	}
}

void handle_ip_packet(arp_entries *arp_table, rt_entries *rt_table, packet *pkt, queue wait_list) {
	struct ether_header *eth_hdr = (struct ether_header *) pkt->payload;
	struct iphdr *ip_hdr = (struct iphdr *) (pkt->payload + IP_OFFSET);

    uint16_t check_received = ip_hdr->check;
    ip_hdr->check = 0;
	ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

	// daca checksum-ul pachetului este incorect, acesta se discard-uieste
    if (ip_hdr->check != check_received) {
       	free(pkt);
		return;
	}

	// daca ttl-ul pachetului a expirat se trimite un mesaj icmp time exceeded sursei
    if (ip_hdr->ttl <= 1) {
		// interfata va fi aleasa in send_icmp_packet in functie de ruta generata de adresa sursa a pachetului, de aceea este marcata cu -1
        send_icmp_packet(arp_table, -1, ip_hdr->saddr, wait_list, rt_table, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, NULL);
		free(pkt);
        return;
    }

	// updateaza ttl-ul
    ip_hdr->ttl--;
    ip_hdr->check = 0;
    ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

    // verifica daca pachetul este adresat unei interfete proprii
	for (int i = 0; i < ROUTER_NUM_INTERFACES; ++i) {
		uint32_t dest_ip = inet_addr(get_interface_ip(i));

		if (coresponding_mac(i, eth_hdr->ether_dhost) && ip_hdr->daddr == dest_ip) {
			packet_for_router_intf(arp_table, i, pkt, wait_list, rt_table);
			return;
		}
	}

	// daca nu se gaseste nicio ruta, se trimite un mesaj icmp destination unreachable
	rt_entry* route =  get_best_route(ntohl(ip_hdr->daddr), rt_table);
	if (route == NULL) {
		send_icmp_packet(arp_table, -1, ip_hdr->saddr, wait_list, rt_table, ICMP_DEST_UNREACH, ICMP_NET_UNREACH, NULL);
		free(pkt);
		return;
	}

	// layer 2 setup	
    get_interface_mac(route->intf, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);
	pkt->interface = route->intf;

	// daca nu se gaseste intrarea in tabela cam pentru adresa next_hop se trimite un arp request pentru aceasta si se pune pachetul "in coada de asteptare"
	arp_entry* ip2mac = get_arp_entry(arp_table, htonl(route->next_hop));
	if (ip2mac == NULL) {
		send_arp_request(arp_table, route->intf, htonl(route->next_hop));
		queue_enq(wait_list, pkt);
		return;
	}

	// daca se gaseste intrarea in tabela cam pentru adresa next_hop se completeaza adresa mac destinatie si se trimite pachetul
    memcpy(eth_hdr->ether_dhost, ip2mac->mac, 6 * sizeof(uint8_t));
    send_packet(pkt->interface, pkt);
	free(pkt);
}

void handle_arp_packet(arp_entries *arp_table, rt_entries *rt_table, packet *pkt, queue wait_list) {
	arp_hdr *arphdr = (arp_hdr *) (pkt->payload + sizeof(struct ether_header));

	for (int i = 0; i < ROUTER_NUM_INTERFACES; ++i) {
		// verifica pe ce interfata a intrat mesajul arp si daca pachetul este destinat acelei interfete
		uint32_t target_ip = inet_addr(get_interface_ip(i));
		if (pkt->interface == i && memcmp(arphdr->dip_addr, &target_ip, 4 * sizeof(uint8_t)) == 0) {
			packet_for_router_intf(arp_table, i, pkt, wait_list, rt_table);
			break;
		}
	}
}

int main(int argc, char *argv[]) {
	setvbuf(stdout, NULL, _IONBF, 0);
	init();

	// routing table setup
	rt_entries *rt_table = (rt_entries *) malloc(sizeof(rt_entries));
	rt_table->len = 0;
	parse_routing_table(rt_table);

	// arp table setup
	arp_entries *arp_table = (arp_entries *) malloc(sizeof(arp_entries));
	arp_table->len = 0;

	queue wait_list = queue_create();

	while (1) {
        // primeste un pachet pe o interfata
		packet* pkt = (packet*) malloc(sizeof(packet));
		int rc = get_packet(pkt);
		DIE(rc < 0, "get_message");

        struct ether_header *eth_hdr = (struct ether_header *) pkt->payload;

		// se verifica ce protocol este incapsulat in frame-ul ethernet pentru gestiona corect pachetul
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			handle_ip_packet(arp_table, rt_table, pkt, wait_list);
		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			handle_arp_packet(arp_table, rt_table, pkt, wait_list);
		}
	}

	// se elibereaza memoria alocata
	free(wait_list);
	free(arp_table);
	free(rt_table);
	return 0;
}
