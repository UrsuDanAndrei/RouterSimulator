#ifndef __ROUTING_TABLE_H__
#define __ROUTING_TABLE_H__

#define MAX_ROUTING_TABLE_SIZE 100000

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


#endif