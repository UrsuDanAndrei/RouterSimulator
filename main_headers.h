#ifndef __MAIN_HEADERS_H__
#define __MAIN_HEADERS_H__

#include <stdio.h>
#include <string.h>

#include "arp.h"
#include "queue.h"
#include "routing_table.h"
#include "icmp.h"
#include "utils.h"

int coresponding_mac(int intf_id, uint8_t* dmac);
void packet_for_router_intf(arp_entries* arp_table, int intf_id,
						   packet* pkt, queue wait_list, rt_entries* rt_table);
void handle_arp_packet(arp_entries *arp_table, rt_entries *rt_table, packet *pkt, queue wait_list);
void handle_ip_packet(arp_entries *arp_table, rt_entries *rt_table, packet *pkt, queue wait_list);

#endif // __MAIN_HEADERS_H__
