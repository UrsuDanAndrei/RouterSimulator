#ifndef __ARP_H__
#define __ARP_H__

#include "skel.h"

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
} arp_entries;

typedef struct {
	uint16_t ar_hrd;                /* Format of hardware address.  */
    uint16_t ar_pro;                /* Format of protocol address.  */
    uint8_t ar_hln;                /* Length of hardware address.  */
    uint8_t ar_pln;                /* Length of protocol address.  */
    uint16_t ar_op;


	uint8_t shw_addr[ETH_ALEN];
	uint8_t sip_addr[IP_ALEN];
    
	uint8_t dhw_addr[ETH_ALEN];
	uint8_t dip_addr[IP_ALEN];
} arp_hdr;

#endif
