#ifndef __UTILS_H__
#define __UTILS_H__

#include "skel.h"

void init_packet(packet* pkt);

uint16_t icmp_checksum(void *vdata, size_t length);
uint16_t checksum(void *vdata, size_t length);
uint16_t ip_checksum(void* vdata,size_t length);

#endif // _UTILS_H__
