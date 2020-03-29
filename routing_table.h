#ifndef __ROUTING_TABLE_H__
#define __ROUTING_TABLE_H__

#include <math.h>

#include "skel.h"

#define IP_OFFSET (sizeof(struct ether_header))
#define MAX_ROUTING_TABLE_SIZE 100000
#define MAX_MASK_SIZE 32
#define MAX_ROUTING_ENTRTY_SIZE 64
#define IP_ALEN 4


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

/* functiile implementate in routing_table.c trebuie sa primeasca parametrii in
format little endian */

/* impune ordinea in care se sorteaza tabela de rutare */
int cmp_route(const void* a, const void* b);

/* citeste tabela statica de rutare si populeaza structura rt_table cu intrarile
citie din fisier */
void parse_routing_table(rt_entries* rt_table);

/* returneaza cea mai buna cale catre dest_ip, realizand o cautare binara cu pas
in structura rt_table */
rt_entry* get_best_route(uint32_t dest_ip, rt_entries* rt_table);

#endif // __ROUTING_TABLE_H__
