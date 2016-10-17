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
#include <stdlib.h>
#include <string.h>

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
  struct sr_if* inf = sr_get_interface(sr, interface);

  print_hdr_eth(packet);

  /*get type of packet*/

  uint16_t etype = (uint16_t)(ethertype(packet));

  /* arp frame handling*/
  if (etype == ethertype_arp){

    printf("arp packet here!\n");
    print_hdr_arp(packet + sizeof(struct sr_ethernet_hdr));

    struct sr_arp_hdr* arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

    struct sr_if* if_walker = sr->if_list;
    int flag = 0;

    while(if_walker)
    {
       if(if_walker->ip == arp_hdr->ar_tip)
        { 
          flag = 1;
          break; }
        if_walker = if_walker->next;
    }

    /*found ip in our list*/

    if(arp_hdr->ar_op == htons(arp_op_request) && flag == 1){
      printf("its a arp request, need to reply\n");
      
      if (inf){

        printf("and we have the interface\n");

        uint8_t *buf = malloc(len);

        struct sr_arp_hdr* arp_response = (struct sr_arp_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
        struct sr_ethernet_hdr* ehdr_response = (struct sr_ethernet_hdr*)buf;

        arp_response->ar_hrd = htons(arp_hrd_ethernet);
        arp_response->ar_pro = htons(ethertype_ip);
        arp_response->ar_hln = 6;
        arp_response->ar_pln = 4;
        arp_response->ar_op = htons(arp_op_reply);


        memcpy(&(arp_response->ar_tha), &(arp_hdr->ar_sha), ETHER_ADDR_LEN * sizeof (char));
        memcpy(&(ehdr_response->ether_dhost), &(arp_hdr->ar_sha), ETHER_ADDR_LEN * sizeof (uint8_t));

        memcpy(&(arp_response->ar_sha), &(if_walker->addr), ETHER_ADDR_LEN * sizeof (char));
        memcpy(&(ehdr_response->ether_shost), &(if_walker->addr), ETHER_ADDR_LEN * sizeof (uint8_t));

        arp_response->ar_tip = (uint32_t)if_walker->ip;
        arp_response->ar_sip = (uint32_t)sr->sr_addr.sin_addr.s_addr;

        ehdr_response->ether_type = (uint16_t)htons(ethertype_arp);

        printf("send the ARP reply\n");

        print_hdr_eth(buf);
        print_hdr_arp(buf + sizeof(struct sr_ethernet_hdr));

        sr_send_packet(sr,buf,len,interface);

        free(buf);
      }

      else{
        printf("drop packet");
      }

    }

  }

  /* ip frame handling*/
  else if (etype == ethertype_ip){

    printf("its an IP packet!\n");
        
    struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

    if(cksum(packet + sizeof(struct sr_ethernet_hdr), ip_hdr->ip_len) != ip_hdr->ip_sum){
      fprintf(stderr,"erro with checksum/n");
    }

    struct sr_if* if_walker = sr->if_list;
    int flag = 0;

    while(if_walker)
    {
       if(if_walker->ip == ip_hdr->ip_dst)
        { 
          flag = 1;
          break; }
        if_walker = if_walker->next;
    }

    /* found ip in our interfaces*/
    if(flag==1){
      
      /* ip frame is for us... check protocol */
      printf("ip frame is for us! lets see what it is\n");
      
      uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));

      /* if its ICMP...*/
      if (ip_proto == ip_protocol_icmp){
        printf("its an ICMP packet!\n");
        struct sr_icmp_hdr* icmp_hdr = (struct sr_icmp_hdr*)(packet +  sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

        if(cksum((packet +  sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)), len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr)) == icmp_hdr->icmp_sum){

          /* if its an echo request*/
          if(icmp_hdr->icmp_type == 0){
            printf("its an echo request!\n");

            
            uint8_t *buf = malloc(len);

            struct sr_icmp_hdr* icmp_res = (struct sr_icmp_hdr*)(buf + sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_ip_hdr));
            struct sr_ip_hdr* ip_res = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
            struct sr_ethernet_hdr* ehdr_res = (struct sr_ethernet_hdr*)buf;

            free(buf);

          }

        }

        /*/check sum didn't pass*/

      }

      /* if its a TCP or UDP protocol*/
      else if(ip_proto == 0x0006 || ip_proto == 0x0011){
        printf("its TCP or UDP!\n");
        
      }

    }























/*
    char* inf_to;*/

    /*sanity check*/
/*    if(cksum(packet + sizeof(struct sr_ethernet_hdr), ip_hdr->ip_len) != ip_hdr->ip_sum &&
      ip_hdr->ip_len < sizeof(struct sr_ip_hdr)){

      printf("checksum didn't work/n");
    }

    printf("passed sanity check!");*/


    /*if(inf == 0){
      struct sr_rt* rt = sr->routing_table;

      struct in_addr ip_addr;
      ip_addr.s_addr = ip_hdr->ip_dst;

      while (rt->next){
        if(inet_ntoa(rt->dest) == inet_ntoa(ip_addr)){

            inf_to = (char *)(rt->interface);
            break;
        }

        rt = rt->next;
      }


      if(inf_to){
        printf("found the interface to pass to in our table!\n");

      }

    }*/


  }

  /*else */
  
}/* end sr_ForwardPacket */

