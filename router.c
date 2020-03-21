#include "skel.h"
#include "main_headers.h"

uint16_t checksum(void *vdata, size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

/* returneaza 1 daca dmac-ul corespunde interfetei intf_id, 0 altfel */
int coresponding_mac(int intf_id, uint8_t* dmac) {
	uint8_t* broadcast_mac = (uint8_t*) malloc(6 * sizeof(uint8_t));
	memset(broadcast_mac, -1, 6 * sizeof(uint8_t));

	// daca este adresa de broadcast inseamna ca interfata corespunde
	if (memcmp(dmac, broadcast_mac, 6 * sizeof(uint8_t)) == 0) {
		return 1;
	}

	uint8_t* intf_mac = (uint8_t*) malloc(6 * sizeof(uint8_t));
	get_interface_mac(intf_id, intf_mac);
	
	if (memcmp(intf_mac, dmac, ETH_ALEN * sizeof(uint8_t)) == 0) {
		return 1;
	}

	return 0;
}

arp_entry* get_arp_entry(arp_entries* arp_table, uint32_t ip) {
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

void init_packet(packet* pkt) {
	memset(pkt->payload, 0, sizeof(pkt->payload));
	pkt->len = 0;
}

void send_arp_request(arp_entries* arp_table, int intf_id, uint32_t target_ip) {
	packet* request = (packet*) malloc(sizeof(packet));
	init_packet(request);
	request->len = sizeof(struct ether_header) + sizeof(struct arp_hdr);

	struct ether_header *eth_hdr = (struct ether_header *) request->payload;
	struct arp_hdr *arphdr = (struct arp_hdr *) request->payload
												+ sizeof(struct ether_header);
	
	// ethernet header setup
	// !!! broadcast bun, ai grija
	// uint8_t* intf_mac = NULL;
	// get_interface_mac(intf_id, intf_mac);
	// memcpy(eth_hdr->ether_shost, intf_mac, 6 * sizeof(uint8_t));
	get_interface_mac(intf_id, eth_hdr->ether_shost);
	memset(eth_hdr->ether_dhost, -1, 6 * sizeof(uint8_t));
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	// arp header setup
	// !!! vezi ca ip sa fie in bigendian
	struct in_addr help;
    help.s_addr = target_ip;
	
	// !!! arp hdrlenght verifica daca merge struc arp_header in loc de arp_hdr
	// arphdr->hlen = 6;
	memcpy(arphdr->shw_addr, eth_hdr->ether_shost, 6 * sizeof(uint8_t));
	memcpy(arphdr->sip_addr, get_interface_ip(intf_id), 4 * sizeof(uint8_t));
	memcpy(arphdr->dip_addr, inet_ntoa(help), 4 * sizeof(uint8_t));
	memset(arphdr->dhw_addr, 0, 6 * sizeof(uint8_t));

	send_packet(intf_id, request);
}

// !!! daca vine un pachet cu ip pt interfata dar nu are mac-ul ei
// !!! ai grija la modul cum aloca get_ip_interface si
// get_mac_interface

void send_icmp_packet(arp_entries* arp_table, int intf_id, uint32_t destip, queue wait_list, rt_entries* rt_table, uint8_t type, uint8_t code) {
	packet* pkt = (packet*) malloc(sizeof(packet));
	init_packet(pkt);
	pkt->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	// layer 3 setup
	struct ether_header *eth_hdr = (struct ether_header*) pkt->payload;
	struct iphdr *ip_hdr = (struct iphdr*) (pkt->payload
								+ IP_OFFSET);
	struct icmphdr *icmp_hdr = (struct icmphdr*)(pkt->payload
 								+ ICMP_OFFSET);
	// !!! se poate sa trebuiasca adaugate mai multe campuri

	// IP setup
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	ip_hdr->ttl = 64;
	ip_hdr->id = htons(getpid() & 0xFFFF);
	ip_hdr->tos = 0;
	ip_hdr->frag_off = 0;
	ip_hdr->tot_len = htons(pkt->len - sizeof(struct ether_header));
	ip_hdr->protocol = 1;

	// !!! adresa sursa / destinatie trebuie sa fie in big endian
	rt_entry* route = get_best_route(ntohl(destip), rt_table);
	// daca trebuie sa dea echo reply, interafata trebuie sa fie intf_id
	if (code == 0 && type == 0) {
		ip_hdr->saddr = inet_addr(get_interface_ip(intf_id));
	} else {
		ip_hdr->saddr = inet_addr(get_interface_ip(route->intf));
	}

	ip_hdr->daddr = destip;

	ip_hdr->check = 0;
	ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

	// ICMP setup
	icmp_hdr->type = type;
    icmp_hdr->code = code;

    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmphdr));

	// layer 2 setup
	arp_entry* ip2mac = get_arp_entry(arp_table, route->next_hop);
	get_interface_mac(route->intf, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);
	pkt->interface = route->intf;

	if (ip2mac == NULL) {
		queue_enq(wait_list, pkt);
		send_arp_request(arp_table, route->intf, route->next_hop);
		return;
	}

		// !!! nu stiu daca trebuie htonl aici, sau trebuie trecut ethertype
		// uint8_t* intf_mac = NULL;
		// get_interface_mac(intf_id, intf_mac);
		// memcpy(eth_hdr_reply->ether_shost, intf_mac, ETH_ALEN * sizeof(uint8_t));
	memcpy(eth_hdr->ether_dhost, ip2mac->mac, ETH_ALEN * sizeof(uint8_t));
}

void packet_for_router_intf(arp_entries* arp_table, int intf_id,
						   packet* pkt, queue wait_list, rt_entries* rt_table) {
	
	struct ether_header *eth_hdr = (struct ether_header *) pkt->payload;
	struct iphdr *ip_hdr = (struct iphdr *) (pkt->payload + IP_OFFSET);

	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
		struct arp_hdr *arphdr = (struct arp_hdr *) pkt->payload
												+ sizeof(struct ether_header);

		// verific daca este un arp request sau un arp reply
		uint32_t ip_intf = inet_addr(get_interface_ip(intf_id));
		uint32_t arp_ip_target = inet_addr((char*) arphdr->dip_addr);
		
		// !!! distinge intre arp request si arp reply
		if (ip_intf == arp_ip_target) {
			// am primit un arp request, raspund cu un arp reply

			// arp header setup
			get_interface_mac(intf_id, arphdr->dhw_addr);

			// ethernet header setup
			memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6 * sizeof(uint8_t));
			get_interface_mac(intf_id, eth_hdr->ether_shost);
			eth_hdr->ether_type = htons(ETHERTYPE_ARP);

			return;
		}

		// am primit arp un reply

		// introduc o noua intrare in arp cache
		++arp_table->len;
		arp_table->entries[arp_table->len - 1].ip = inet_addr((char*) arphdr->dip_addr);
		memcpy(arp_table->entries[arp_table->len -1].mac, arphdr->dhw_addr, 6 * sizeof(uint8_t));

		// verific daca pot pleca pachete acum
		// !!! se poate sa trebuiasca verificata toata coada, nu doar pirmul pachet
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
			} else {
				queue_enq(copy, waiting_pkt);
			}
		}

		while (!queue_empty(copy)) {
			queue_enq(wait_list, queue_deq(copy));
		}
		
		return;
	}

	// !!! punde contditia ca eht_hdr->ether_type == ETHERTYPE_IP
	if (ip_hdr->protocol == 1) {
		struct icmphdr *icmp_hdr = (struct icmphdr *) (pkt->payload
									+ ICMP_OFFSET);

		// !!! nu stiu daca trebuie acest if
		// discard-uieste pachetul daca nu este icmp echo request
		if (icmp_hdr->type != 8 || icmp_hdr->code != 0) {
			return;
		}

		send_icmp_packet(arp_table, intf_id, ip_hdr->saddr, wait_list, rt_table, 0, 0);

		// daca este un icmp echo request se raspunde cu un icmp echo reply
		// packet* reply = (packet*) malloc(sizeof(packet));
		// init_packet(reply);
		// reply->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

		// // layer 3 setup
		// struct ether_header *eth_hdr_reply = (struct ether_header*) reply->payload;
		// struct iphdr *ip_hdr_reply = (struct iphdr*) (reply->payload
		// 							+ IP_OFFSET);
		// struct icmphdr *icmp_hdr_reply = (struct icmphdr*)(reply->payload
		//  							+ ICMP_OFFSET);
		// // !!! se poate sa trebuiasca adaugate mai multe campuri

		// // IP setup
		// ip_hdr_reply->version = 4;
		// ip_hdr_reply->ihl = 5
		// ip_hdr_reply->ttl = 64;
		// ip_hdr_reply->id = htons(getpid() & 0xFFFF);
		// ip_hdr_reply->tos = 0;
		// ip_hdr_reply->frag_off = 0;
		// ip_hdr_reply->tot_len = htons(reply->len - sizeof(struct ether_header));
		// ip_hdr_reply->protocol = 1;

		// // !!! adresa sursa / destinatie trebuie sa fie in big endian
		// ip_hdr_reply->saddr = inet_addr(get_interface_ip(intf_id));
		// ip_hdr_reply->daddr = ip_hdr->saddr;

		// ip_hdr_reply->check = 0;
		// ip_hdr_reply->check = checksum(ip_hdr, sizeof(struct iphdr));

		// // ICMP setup
		// icmp_hdr_reply->type = 0;
        // icmp_hdr_reply->code = 0;

        // icmp_hdr_reply->checksum = 0;
        // icmp_hdr_reply->checksum = checksum(icmp_hdr_reply, sizeof(struct icmphdr));

		// // layer 2 setup
		// rt_entry* route = get_best_route(ntohl(ip_hdr_reply->daddr), rt_table);
		// // !!! nu stiu daca trebuie htonl aici, sau trebuie trecut ethertype
		// // uint8_t* intf_mac = NULL;
		// // get_interface_mac(intf_id, intf_mac);
		// // memcpy(eth_hdr_reply->ether_shost, intf_mac, ETH_ALEN * sizeof(uint8_t));
		// get_interface_mac(intf_id, eth_hdr_reply->ether_shost);
		// memcpy(eth_hdr_reply->ether_dhost, ip2mac->mac, ETH_ALEN * sizeof(uint8_t));

		// if (ip2mac == NULL) {
		// 	enque(reply, wait_list);
		// 	send_arp_request(arp_table, route->intf, ip_hdr->daddr);
		// 	return;
		// }

		// arp_entry* ip2mac = get_arp_entry(arp_table, route->next_hop);
		// eth_hdr_reply->ether_type = htons(ETHERTYPE_IP);
	}
}

int cmp_route(const void* a, const void* b) {
	rt_entry* entry1 = (rt_entry*) a;
	rt_entry* entry2 = (rt_entry*) b;

	if (entry1->mask == entry2->mask) {
		if (entry1->network < entry2->network) {
			return -1;
		}

		return 1;
	} else if (entry1->mask < entry2->mask) {
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
		rt_table->entries[i].network = ntohl(inet_addr(info));

		info = strtok(NULL, " ");
		rt_table->entries[i].next_hop = ntohl(inet_addr(info));

		info = strtok(NULL, " ");
		rt_table->entries[i].mask = ntohl(inet_addr(info));

		info = strtok(NULL, " ");
		rt_table->entries[i].intf = atoi(info);
		
		++i;
	}
	
	// se sorteaza tabela de rutare
	rt_table->len = i;
	qsort(rt_table->entries, rt_table->len, sizeof(rt_entry), cmp_route);

	for (int j = 0; j < rt_table->len; ++j) {
		struct in_addr help;
    	help.s_addr = htonl(rt_table->entries[j].mask);

		printf("%s ", inet_ntoa(help));

		help.s_addr = htonl(rt_table->entries[j].network);
		printf("%s ", inet_ntoa(help));

		help.s_addr = htonl(rt_table->entries[j].next_hop);
		printf("%s ", inet_ntoa(help));

		printf("%d\n", rt_table->entries[j].intf);
	}
}


// cred ca greseala este in tablea de rutare la  adresa cu masca 255.255.0.0
rt_entry* get_best_route(uint32_t dest_ip, rt_entries* rt_table) {
	int msb = log2(rt_table->len);
	// printf("msb: %d, length: %d\n", msb, rt_table->len);

	// uint32_t dest_ip = ntohl(inet_addr("192.168.6.9"));
	// struct in_addr help;
	// help.s_addr = htonl(dest_ip);
	// printf("%s \n", inet_ntoa(help));

	// se cauta intrarea cu cea mai lunga masca de retea
	for (int mask_size = MAX_MASK_SIZE; mask_size >= 0; --mask_size) {
		uint32_t mask = ((1LL << MAX_MASK_SIZE) - 1)
						<< (MAX_MASK_SIZE - mask_size);

		int left = 0;
		int right = 0;

		/* se cauta binar un interval [left, right] in care se regasesc numai 
		intrari cu masca egala cu mask */
		for (int bit = msb; bit >= 0; --bit) {
			int index = left + (1 << bit);
			if (index < rt_table->len && rt_table->entries[index].mask < mask) {
				left += (1 << bit);
			}
		}

		if (rt_table->entries[0].mask != mask) {
			++left;
		}

		for (int bit = msb; bit >= 0; --bit) {
			int index = right + (1 << bit);
			if (index < rt_table->len
				&& rt_table->entries[index].mask <= mask) {
				right += (1 << bit);
			}
		}

		// se cauta binar un match pentru adresa data ca parametru
		int answer = left;
		// printf("left: %d, right: %d, ", left, right);
		uint32_t network = dest_ip & mask;

		for (int bit = log2(right); bit >= 0; --bit) {
		//printf("%d  %d\n", index, bit);
			int index = answer + (1 << bit);
			if (index < rt_table->len
				&& rt_table->entries[index].network <= network) {
				answer += (1 << bit); 
			}
		}
	// printf("answer: %d, retea: ", answer);
	// 		uint32_t dest_ip2 = network;
	// struct in_addr help2;
	// help2.s_addr = htonl(dest_ip2);
	// printf("%s \n", inet_ntoa(help2));




		if (rt_table->entries[answer].network == network) {
			//printf("answer: %d\n", answer);
			return &rt_table->entries[answer];
		}
	}
	//printf("aaaaaaaaaa\n");
	return NULL;
}



int main(int argc, char *argv[])
{
	// setvbuf(stdout, NULL, _IONBF, 0);
	int rc;
	//return 0;
	//init();
	//return 0;
	printf("ceva\n");

	// --------------------------------
	rt_entries rt_table;
	parse_routing_table(&rt_table);

	uint32_t dest_ip = ntohl(inet_addr("192.1.5.1"));
	struct in_addr help;
	help.s_addr = htonl(get_best_route(rt_table.entries[2].network, &rt_table)->network);
	printf("reteaua gasita: %s \n", inet_ntoa(help));

	//printf("%d\n", get_best_route(rt_table.entries[2].network, &rt_table));
	return 0;

	// ------------------------------

	arp_entries arp_table;
	queue wait_list = queue_create();

	while (1) {
        // primeste un pachet de la o interfata
		packet* pkt = (packet*) malloc(sizeof(packet));
		rc = get_packet(pkt);
		DIE(rc < 0, "get_message");

        struct ether_header *eth_hdr = (struct ether_header *) pkt->payload;
		struct iphdr *ip_hdr = (struct iphdr *) (pkt->payload + IP_OFFSET);

        uint16_t check_received = ip_hdr->check;
        ip_hdr->check = 0;
		ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

        if (ip_hdr->check != check_received) {
            continue;
        }

        if (ip_hdr->ttl <= 1) {
            send_icmp_packet(&arp_table, 0, ip_hdr->saddr, wait_list, &rt_table, 11, 0);
            continue;
        }

        ip_hdr->ttl--;
        ip_hdr->check = 0;
        ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

        // verifica daca pachetul este adresat unei interfete proprii
		int continue_while = 0;
		for (int i = 0; i < ROUTER_NUM_INTERFACES; ++i) {
			if (coresponding_mac(i, eth_hdr->ether_dhost)) {
				// !!! verifica sa primeasca si pachetele de broadcast
				packet_for_router_intf(&arp_table, i, pkt, wait_list, &rt_table);
				continue_while = 1;
				break;
			}
		}

		if (continue_while) {
			continue;
		}

		rt_entry* route =  get_best_route(ip_hdr->daddr, &rt_table);
		if (route == NULL) {
			send_icmp_packet(&arp_table, 0, ip_hdr->saddr, wait_list, &rt_table, 3, 0);
		}
		
		arp_entry* ip2mac = get_arp_entry(&arp_table, route->next_hop);
        get_interface_mac(route->intf, eth_hdr->ether_shost);
		eth_hdr->ether_type = htons(ETHERTYPE_IP);
		pkt->interface = route->intf;

		if (ip2mac == NULL) {
			send_arp_request(&arp_table, route->intf, route->next_hop);
			queue_enq(wait_list, pkt);
			continue;
		}

        memcpy(eth_hdr->ether_dhost, ip2mac->mac, 6 * sizeof(uint8_t));
        send_packet(route->intf, pkt);
		// dirijeaza corespunzator pachetul
	}
}
