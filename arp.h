#ifndef __ARP_H__
#define __ARP_H__

#include "skel.h"
#include "utils.h"
#include "routing_table.h"

#define MAX_ARP_TABLE_SIZE 1000
#define ARP_OFFSET (sizeof(struct ether_header))

typedef struct {
    uint32_t ip;
	uint8_t mac[ETH_ALEN];
} arp_entry;

typedef struct {
    arp_entry entries[MAX_ARP_TABLE_SIZE];
    int len;
} arp_entries ;

typedef struct {
	uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;


	uint8_t shw_addr[ETH_ALEN];
	uint8_t sip_addr[IP_ALEN];
    
	uint8_t dhw_addr[ETH_ALEN];
	uint8_t dip_addr[IP_ALEN];
} arp_hdr;

/* cauta intrarea specifica adresei ip trimisa ca parametru in structura
arp table */
arp_entry* get_arp_entry(arp_entries *arp_table, uint32_t ip);

/* trimite un mesaj de tipul arp request de pe interfata intf_id pentru aflarea
mac-ului corespunzator adresei target_ip */
void send_arp_request(arp_entries *arp_table, int intf_id, uint32_t target_ip);

/* raspunde cu un mesaj arp reply (la mesajul arp request pkt) ce va contine
adresa mac a interfetei intf_id */
void send_arp_reply(int intf_id, packet *pkt);

/* poate introduce o noua intrare in tabela arp */
void update_arp_table(arp_entries *arp_table, arp_entry *new_entry);

#endif // __ARP_H__
