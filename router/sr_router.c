/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  
  /* interface check to see if we have it */
  struct sr_if* inf_from = sr_get_interface(sr, interface);

  /* ethernet header */
  struct sr_ethernet_hdr* ehdr = (struct sr_ethernet_hdr*)packet;
  /*print the destination and source addresses*/

  print_hdr_eth(packet);

  /*get type of packet*/

  uint16_t etype = (uint16_t)(ethertype(packet));

  /* arp frame handling*/
  if (etype == ethertype_arp){

    printf("arp packet here!/n");
    print_hdr_arp(packet + sizeof(struct sr_ethernet_hdr));

    struct sr_arp_hdr* arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

    if (sr_arp_req_not_for_us(sr, packet, len, interface) == 1){
      printf("the arp is not for us\n");
      /*its not for us*/

    }

    else if(arp_hdr->ar_op == htons(arp_op_request)){
      printf("its a arp request, need to reply");
      
      if (inf_from){

        unsigned char *packet_out = 0;

        if((packet_out = malloc(len)) == 0){
          fprintf(stderr,"Error: out of memory (sr_read_from_server)\n");
          return -1;
          
        }

        sr_arp_hdr_t arp_response = (struct sr_arp_hdr*)(packet_out + sizeof(struct sr_ethernet_hdr));
        
        arp_response->ar_hrd = htons(sr_arp_hrd_fmt);
        arp_response->ar_pro = htons(ethertype_ip);
        arp_response->ar_hln = 6;
        arp_response->ar_pln = 4;
        arp_response->ar_op = htons(arp_op_reply);

        arp_response->ar_sha = inf_from->addr; 
        arp_response->ar_sip = (uint32_t)sr.sr_addr.sin_addr.s_addr;
        arp_response->ar_tha = arp_hdr->ar_sha;
        arp_response->ar_tip = arp_hdr->ar_sip;

        struct sr_ethernet_hdr* ehdr_response = (struct sr_ethernet_hdr*)packet_out;

        ehdr_response->ether_dhost = arp_hdr->ar_sha;
        ehdr_response->ether_shost = inf_from->addr;
        ehdr_response->ether_type = htons(ethertype_arp);

        printf("send the ARP reply\n");
        sr_send_packet(sr,packet_out,len,interface);

      }

    }

  }

  /* ip frame handling*/
  else if (etype == ethertype_ip){

    printf("its an IP packet!\n");

    struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    char* inf_to;

    /*sanity check*/
    if(cksum(packet + sizeof(struct sr_ethernet_hdr), ip_hdr->ip_len) != ip_hdr->ip_sum &&
      ip_hdr->ip_len < sizeof(struct sr_ip_hdr)){

      printf("checksum didn't work/n");
    }

    printf("passed sanity check!");

    /* interface_to not in our if_list*/
    if(inf_from == 0){
      struct sr_rt* rt = sr->routing_table;

      struct in_addr ip_addr;
      ip_addr.s_addr = ip_hdr->ip_dst;

      /* find the interface of the destination*/
      while (rt->next){
        if(inet_ntoa(rt->dest) == inet_ntoa(ip_addr)){
            /* found destination in routing_table*/
            inf_to = (char *)(rt->interface);
            break;
        }

        rt = rt->next;
      }

      /* destination is in our table...*/
      if(inf_to){
        printf("found the interface to pass to in our table!\n");

      }

      /*else send ICMP net unreachable*/

    }

    /* ip frame is for us... check protocol */
    printf("ip frame is for us! lets see what it is\n");
    uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));

    /* if its ICMP...*/
    if (ip_proto == ip_protocol_icmp){
      printf("its an ICMP packet!\n");
      struct sr_icmp_hdr* icmp = (struct sr_icmp_hdr*)(packet +  sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

      if(cksum(packet + sizeof(struct sr_ethernet_hdr), ip_hdr->ip_len) == ip_hdr->ip_sum){

        /* if its an echo request*/
        if(icmp->icmp_type == 0){
          printf("its an echo request!\n");
        }

      }

      /*/check sum didn't pass*/

    }

    /* if its a TCP or UDP protocol*/
    else if(ip_proto == 0x0006 || ip_proto == 0x0011){
      printf("its TCP or UDP!\n");
      
    }


  }

  /*else */
  
}/* end sr_ForwardPacket */

