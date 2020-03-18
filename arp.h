#ifndef __ARP_H__
#define __ARP_H__

#include "skel.h"

#define MAC_SIZE
#define MAX_ARP_SIZE 1000

typedef struct {
    __u32 ip;
	uint8_t mac[MAC_SIZE];
} arp_entry;

typedef struct {
    arp_entry entries[MAX_ARP_SIZE];
    int len;
} arp_table_entries;

#endif
