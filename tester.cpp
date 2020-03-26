#include <stdio.h>

struct arp_hdr {
	__uint16_t ar_hrd;                /* Format of hardware address.  */
    __uint16_t ar_pro;                /* Format of protocol address.  */
    __uint8_t ar_hln;                /* Length of hardware address.  */
    __uint8_t ar_pln;                /* Length of protocol address.  */
    __uint16_t ar_op; 


	__uint8_t shw_addr[6];	
    __uint8_t sip_addr[4];
    
	__uint8_t dhw_addr[6];	
	__uint8_t dip_addr[4];
};

int main() {
	printf("%d\n", sizeof(struct arp_hdr));
	return 0;
}