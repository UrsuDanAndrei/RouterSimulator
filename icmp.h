#ifndef __ICMP_H__
#define __ICMP_H__

#include "arp.h"
#include "queue.h"
#include "routing_table.h"
#include "utils.h"

#define ICMP_OFFSET (IP_OFFSET + sizeof(struct iphdr))
#define ICMP_HEADER_LENGTH 64

/* functie responsabila de trimiterea pachetelor icmp, raspunde la icmp request
cu icmp reply, trimite pachete de control corespunzatoare pentru parametrii
type si code, trimite arp request-uri cand este nevoie */
void send_icmp_packet(arp_entries* arp_table, int intf_id, uint32_t destip, 
                            queue wait_list, rt_entries* rt_table, uint8_t type,
                                             uint8_t code, packet* pkt_recv);

#endif // __ICMP_H__
