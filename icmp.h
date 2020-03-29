#ifndef __ICMP_H__
#define __ICMP_H__

#include "arp.h"
#include "queue.h"
#include "routing_table.h"
#include "utils.h"

#define ICMP_OFFSET (IP_OFFSET + sizeof(struct iphdr))
#define ICMP_HEADER_LENGTH 64

void send_icmp_packet(arp_entries* arp_table, int intf_id, uint32_t destip, queue wait_list, rt_entries* rt_table, uint8_t type, uint8_t code, packet* pkt_recv);

#endif // __ICMP_H__
