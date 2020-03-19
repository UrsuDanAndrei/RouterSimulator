#ifndef __ARP_H__
#define __ARP_H__

#include "skel.h"

#define MAC_SIZE 6
#define MAX_ARP_TABLE_SIZE 1000
#define ARP_CODE 2048

typedef struct {
    __u32 ip;
	uint8_t mac[MAC_SIZE];
} arp_entry;

typedef struct {
    arp_entry entries[MAX_ARP_TABLE_SIZE];
    int len;
} arp_entries;

#endif
