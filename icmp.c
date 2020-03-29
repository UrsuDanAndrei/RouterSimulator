#include "icmp.h"

void send_icmp_packet(arp_entries* arp_table, int intf_id, uint32_t destip, queue wait_list, rt_entries* rt_table, uint8_t type, uint8_t code, packet* pkt_recv) {
	// packet setup
	packet* pkt;
	if (type == 0 && code == 0) {
		// pentru ca echo reply sa corespunda cu echo request, se utilizeaza acelasi pachet
		pkt = pkt_recv;
	} else {
		pkt = (packet*) malloc(sizeof(packet));
		init_packet(pkt);
		pkt->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	}

	struct ether_header *eth_hdr = (struct ether_header*) pkt->payload;
	struct iphdr *ip_hdr = (struct iphdr*) (pkt->payload
								+ IP_OFFSET);
	struct icmphdr *icmp_hdr = (struct icmphdr*) (pkt->payload
 								+ sizeof(struct ether_header) + sizeof(struct iphdr));
	// IP setup
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	ip_hdr->ttl = 64;
	ip_hdr->id = htons(getpid() & 0xFFFF);
	ip_hdr->tos = 0;
	ip_hdr->frag_off = 0;
	ip_hdr->tot_len = htons(pkt->len - sizeof(struct ether_header));
	ip_hdr->protocol = 1;
	ip_hdr->daddr = destip;

	rt_entry* route = get_best_route(ntohl(destip), rt_table);
	pkt->interface = route->intf;

	// daca trebuie sa dea echo reply, sursa ip trebuie sa fie intf_id
	if (code == 0 && type == 0) {
		ip_hdr->saddr = inet_addr(get_interface_ip(intf_id));
	} else {
		// altfel poate fi interfata pe care o sa plece pachetul
		ip_hdr->saddr = inet_addr(get_interface_ip(route->intf));
	}

	ip_hdr->check = 0;
	ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

	// ICMP setup
	icmp_hdr->type = type;
    icmp_hdr->code = code;

    icmp_hdr->checksum = 0;
   	icmp_hdr->checksum = icmp_checksum(icmp_hdr, ICMP_HEADER_LENGTH);

	// layer 2 setup
	get_interface_mac(route->intf, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);

	// daca nu stiu mac-ul pt route->next_hop fac un arp request
	arp_entry* ip2mac = get_arp_entry(arp_table, htonl(route->next_hop));
	if (ip2mac == NULL) {
		queue_enq(wait_list, pkt);
		send_arp_request(arp_table, route->intf, htonl(route->next_hop));
		return;
	}

	memcpy(eth_hdr->ether_dhost, ip2mac->mac, 6 * sizeof(uint8_t));
	send_packet(pkt->interface, pkt);
	free(pkt);
}
