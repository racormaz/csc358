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
  
  /* interface */
  struct sr_if inf_from = (struct sr_if*)(sr_get_interface(sr, interface));

  /* ethernet header */
  struct sr_ethernet_hdr *ehdr = (struct sr_ethernet_hdr*)packet;
  /*print the destination and source addresses*/

  print_hdr_eth(packet);

  /*get type of packet*/

  uint16_t etype = (uint16_t)(ethertype(packet->buffer));

  /* arp frame handling*/
/*  if (etype == ethertype_arp){

    struct sr_arp_hdr* arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

    if (ehder->etehr_dhost == "ff-ff-ff-ff-ff-ff"){


    }
  }*/

  /* ip frame handling*/
  if (etype == ethertype_ip){

    printf("its an IP packet!\n");

    struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    char* inf_to = null;

    /*sanity check*/
    if(cksum(packet + sizeof(struct sr_ethernet_hdr), ip_hdr->ip_len) != ip_hdr->ip_sum &&
      ip_hdr->ip_len < sizeof(struct sr_ip_hdr)){

      return -1;
    }

    printf("passed sanity check!");

    /* interface_to not in our if_list*/
    if(inf_from == 0){
      struct sr_rt* rt = sr->routing_table;

      struct in_addr ip_addr;
      ip_addr.s_addr = iphdr->ip_dst;

      /* find the interface of the destination*/
      while (rt->next != null){
        if(inet_ntoa(rt->dest) == inet_ntoa(ip_addr)){
            /* found destination in routing_table*/
            inf_to = (char *)(rt->interface);
            break;
        }

        rt = rt->next;
      }

      /* destination is in our table...*/
      if(inf_to != null){
        printf("found the interface to pass to
         in our table!\n");

      }

      /*else send ICMP net unreachable*/

    }

    /* ip frame is for us... check protocol */
    printf("ip frame is for us! lets see what it is\n");
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    /* if its ICMP...*/
    if (ip_proto == ip_protocol_icmp){
      printf("its an ICMP packet!\n");
      struct sr_icmp_hdr icmp = (struct sr_icmp_hdr *)(packet +  sizeof(struct sr_ethernet_hdr) 
                                                       + sizeof(struct sr_ip_hdr));

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

