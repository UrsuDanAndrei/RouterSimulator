#ifndef __UTILS_H__
#define __UTILS_H__

#include "skel.h"

/* initializeaza cu 0 lungimea si payload-ul pachetului primit ca parametru */
void init_packet(packet* pkt);

/* returneaza suma de control pentru header-ul primit ca parametru */
uint16_t checksum(void *vdata, size_t length);

#endif // _UTILS_H__
