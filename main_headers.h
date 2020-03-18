#ifndef __MAIN_HEADERS_H__
#define __MAIN_HEADERS_H__

#define IP_OFFSET (sizeof(struct ether_header))
#define ICMP_OFFSET (IP_OFFSET + sizeof(struct iphdr))

int same_mac(int intf_id, uint8_t* dmac);

#endif