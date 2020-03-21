#ifndef __ARP_H__
#define __ARP_H__

#include "skel.h"

#define MAX_ARP_TABLE_SIZE 1000
#define ARP_CODE 2048
#define IP_ALEN 4

typedef struct {
    __u32 ip;
	uint8_t mac[ETH_ALEN];
} arp_entry;

typedef struct {
    arp_entry entries[MAX_ARP_TABLE_SIZE];
    int len;
} arp_entries;

// struct arp_hdr {
// 	uint8_t shw_addr[ETH_ALEN];	
// 	uint8_t sip_addr[IP_ALEN];
    
// 	uint8_t dhw_addr[ETH_ALEN];	
// 	uint8_t dip_addr[IP_ALEN];
// };

#endif
