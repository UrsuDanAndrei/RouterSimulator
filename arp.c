#include "arp.h"

arp_entry* get_arp_entry(arp_entries* arp_table, uint32_t ip) {
	for (int i = 0; i < arp_table->len; ++i) {
        if (arp_table->entries[i].ip == ip) {
            return &arp_table->entries[i];
        }
    }

    return NULL;
}

void send_arp_request(arp_entries* arp_table, int intf_id, uint32_t target_ip) {
	// packet setup
	packet* request = (packet*) malloc(sizeof(packet));
	init_packet(request);
	request->len = sizeof(struct ether_header) + sizeof(arp_hdr);
	request->interface = intf_id;

	struct ether_header *eth_hdr = (struct ether_header *) request->payload;
	arp_hdr *arphdr = (arp_hdr *) (request->payload
												+ sizeof(struct ether_header));
	
	// arp header setup
	arphdr->ar_hrd = htons(1);
	arphdr->ar_pro = htons(0x800);
	arphdr->ar_hln = 6;
	arphdr->ar_pln = 4;
	arphdr->ar_op = htons(1);

	uint32_t sip_addr_int = inet_addr(get_interface_ip(intf_id));
	get_interface_mac(intf_id, arphdr->shw_addr);
	memcpy(arphdr->sip_addr, &sip_addr_int, 4 * sizeof(uint8_t));
	memcpy(arphdr->dip_addr, &target_ip, 4 * sizeof(uint8_t));
	memset(arphdr->dhw_addr, 0, 6 * sizeof(uint8_t));

	// ethernet header setup
	get_interface_mac(intf_id, eth_hdr->ether_shost);

	// se seteaza adresa destinatie ca broadcast
	memset(eth_hdr->ether_dhost, -1, 6 * sizeof(uint8_t));
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	send_packet(intf_id, request);
	free(request);
}

void update_arp_table(arp_entries *arp_table, arp_entry *new_entry) {
	// verifica daca nu exita deja acea intrarea in tabela arp (caz in care ar face update la timpul de expirare)
	int len = arp_table->len;
	for (int i = 0; i < len; ++i) {
		if (arp_table->entries[i].ip == new_entry->ip &&
		arp_table->entries[i].mac == new_entry->mac) {
			return;
		}
	}

	// daca intrarea nu se gaseste in tabela arp, se introduce noua intrare in tabela
	memcpy(&arp_table->entries[len].ip, &new_entry->ip,  IP_ALEN * sizeof(uint8_t));
	memcpy(arp_table->entries[len].mac, new_entry->mac, ETH_ALEN * sizeof(uint8_t));
	++arp_table->len;
}
