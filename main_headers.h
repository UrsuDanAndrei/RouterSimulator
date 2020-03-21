#ifndef __MAIN_HEADERS_H__
#define __MAIN_HEADERS_H__

#include <stdio.h>
#include <string.h>
#include <math.h>
#include "arp.h"
#include "queue.h"
#include "routing_table.h"

#define IP_OFFSET (sizeof(struct ether_header))
#define ICMP_OFFSET (IP_OFFSET + sizeof(struct iphdr))
#define MAX_ROUTING_ENTRTY_SIZE 64

int coresponding_mac(int intf_id, uint8_t* dmac);
rt_entry* get_best_route(uint32_t dest_ip, rt_entries* rt_table);
arp_entry* get_arp_entry(arp_entries* arp_table, uint32_t ip);
void init_packet(packet* pkt);
void send_arp_request(arp_entries* arp_table, int intf_id, uint32_t target_ip);
void send_icmp_packet(arp_entries* arp_table, int intf_id, uint32_t destip, queue wait_list, rt_entries* rt_table, uint8_t type, uint8_t code);
void packet_for_router_intf(arp_entries* arp_table, int intf_id,
						   packet* pkt, queue wait_list, rt_entries* rt_table);
int cmp_route(const void* a, const void* b);
void parse_routing_table(rt_entries* rt_table);
rt_entry* get_best_route(uint32_t dest_ip, rt_entries* rt_table);


#endif