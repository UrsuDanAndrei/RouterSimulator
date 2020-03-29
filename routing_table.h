#ifndef __ROUTING_TABLE_H__
#define __ROUTING_TABLE_H__

#include <math.h>

#include "skel.h"

#define IP_OFFSET (sizeof(struct ether_header))
#define MAX_ROUTING_TABLE_SIZE 100000
#define MAX_MASK_SIZE 32
#define MAX_ROUTING_ENTRTY_SIZE 64

typedef struct {
	uint32_t network;
	uint32_t next_hop;
	uint32_t mask;
	int intf;
} rt_entry;

typedef struct {
    rt_entry entries[MAX_ROUTING_TABLE_SIZE];
    int len;
} rt_entries;

int cmp_route(const void* a, const void* b);
void parse_routing_table(rt_entries* rt_table);
rt_entry* get_best_route(uint32_t dest_ip, rt_entries* rt_table);

#endif // __ROUTING_TABLE_H__
