#ifndef __ARP_H__
#define __ARP_H__

#include "skel.h"
#include "utils.h"

#define MAX_ARP_TABLE_SIZE 1000
#define ARP_CODE 2048
#define IP_ALEN 4

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

arp_entry* get_arp_entry(arp_entries *arp_table, uint32_t ip);
void send_arp_request(arp_entries *arp_table, int intf_id, uint32_t target_ip);
void update_arp_table(arp_entries *arp_table, arp_entry *new_entry);

#endif // __ARP_H__
