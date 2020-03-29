#ifndef __MAIN_HEADERS_H__
#define __MAIN_HEADERS_H__

#include <stdio.h>
#include <string.h>

#include "arp.h"
#include "queue.h"
#include "routing_table.h"
#include "icmp.h"
#include "utils.h"

/* returneaza 1 daca dmac-ul corespunde interfetei intf_id, 0 altfel */
int coresponding_mac(int intf_id, uint8_t* dmac);

/* daca un pachet este adresat unei interfete a router-ului atunci aceasta 
functie se va ocupa de pachet: va raspunde la icmp request-uri cu icmp reply, 
va raspunde la arp request-uri cu arp reply si se va ocupa de arp reply-urile
pentru care router-ul a trimis arp request-uri */
void packet_for_router_intf(arp_entries* arp_table, int intf_id,
						   packet* pkt, queue wait_list, rt_entries* rt_table);

/* functie responsabila de gestionarea pachetelor ARP care trec prin router */
void handle_arp_packet(arp_entries *arp_table, rt_entries *rt_table, packet *pkt, queue wait_list);

/* functie responsabila de gestionarea pachetelor IP care trec prin router */
void handle_ip_packet(arp_entries *arp_table, rt_entries *rt_table, packet *pkt, queue wait_list);

/* verifica daca pot pleca pachete din waiting_list, (m-am gandit ca exista
posibilitatea sa plece si alte pachete inafara de primele din coada,
de aceea o parcurge pe toata) */
void empty_wait_list(arp_entries *arp_table, queue wait_list);

#endif // __MAIN_HEADERS_H__
