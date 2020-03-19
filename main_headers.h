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


int same_mac(int intf_id, uint8_t* dmac);

#endif