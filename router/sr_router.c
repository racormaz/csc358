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
#include <time.h>

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
  printf("\n");
  printf("*** -> Received packet of length %d \n",len);

  print_hdr_eth(packet);

  /*get type of packet*/

  uint16_t etype = (uint16_t)(ethertype(packet));

  /* arp frame handling*/
  if (etype == ethertype_arp){

    printf("arp packet here!\n");
    printf("-------------------------------------------\n");
    print_hdr_arp(packet + sizeof(struct sr_ethernet_hdr));

    struct sr_arp_hdr* arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

    struct sr_if* if_walker = sr->if_list;
    int flag = 0;

    while(if_walker)
    {
       if(if_walker->ip == arp_hdr->ar_tip)
        { /*we have the interface mapped to this IP*/
          flag = 1;
          break; }
        if_walker = if_walker->next;
    }

    if(arp_hdr->ar_op == htons(arp_op_request)){

      if (flag==1){
        printf("its a arp request, need to reply\n");

        /*cache it maybe?*/

        uint8_t *bufAR = malloc(sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_arp_hdr));

        struct sr_arp_hdr* arp_response = (struct sr_arp_hdr*)(bufAR + sizeof(struct sr_ethernet_hdr));
        struct sr_ethernet_hdr* ehdr_response = (struct sr_ethernet_hdr*)bufAR;

        arp_response->ar_hrd = htons(arp_hrd_ethernet);
        arp_response->ar_pro = htons(ethertype_ip);
        arp_response->ar_hln = ETHER_ADDR_LEN;
        arp_response->ar_pln = 4;
        arp_response->ar_op = htons(arp_op_reply);

        memcpy(&(arp_response->ar_tha), &(arp_hdr->ar_sha), ETHER_ADDR_LEN * sizeof (char));
        memcpy(&(ehdr_response->ether_dhost), &(arp_hdr->ar_sha), ETHER_ADDR_LEN * sizeof (uint8_t));

        memcpy(&(arp_response->ar_sha), &(if_walker->addr), ETHER_ADDR_LEN * sizeof (char));
        memcpy(&(ehdr_response->ether_shost), &(if_walker->addr), ETHER_ADDR_LEN * sizeof (uint8_t));

        arp_response->ar_tip = (uint32_t)arp_hdr->ar_sip;
        arp_response->ar_sip = (uint32_t)if_walker->ip;

        ehdr_response->ether_type = (uint16_t)htons(ethertype_arp);

        printf("send the ARP reply\n");

        print_hdr_eth(bufAR);
        print_hdr_arp(bufAR + sizeof(struct sr_ethernet_hdr));
        printf("------------------------------\n");

        sr_send_packet(sr,bufAR,sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_arp_hdr),if_walker->name);

        free(bufAR);
      }

      else{

      }
    }

    /*its a reply
    cache it*/
    else{

      if(flag==1){
        /*cache it*/
        printf("arp reply here!\n");
        printf("-------------------------------------------\n");
        struct sr_arpcache* cache = (struct sr_arpcache*)&(sr->cache); 

        /* we have an IP to MAC mapping so cache it*/
        struct sr_arpreq* req = sr_arpcache_insert(cache,arp_hdr->ar_sha,arp_hdr->ar_sip);

        /*need to remove req from*/
        if(req){
          /*first forward packets that were also waiting on this request*/
          struct sr_packet* pkts = (struct sr_packet*)(req->packets);
          
          /*MAC ADDRESS YAS*/
          unsigned char* mac_dst = arp_hdr->ar_sha;

          while(pkts->next){
            
            uint8_t* bufARR = pkts->buf;
            /*send the packets with the mac address we just got*/
            struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)bufARR;
            struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(bufARR + sizeof(struct sr_ethernet_hdr));

            /*sanity check*/
            uint16_t ck = ip_hdr->ip_sum;

            ip_hdr->ip_sum = 0;

            if(cksum((bufARR + sizeof(struct sr_ethernet_hdr)), sizeof(struct sr_ip_hdr)) != ck){

              fprintf(stderr, "checksum didn't work\n");
            }

            ip_hdr->ip_sum = ck;

            if(ip_hdr->ip_len < sizeof(struct sr_ip_hdr)){
              fprintf(stderr, "not long enough.\n");
            }

            else{
              printf("passed sanity check!\n");

              /* put MAC address in header of Ethernet packet and change checksum of 
              IP packet after decreasing TTL*/

              if(((ip_hdr->ip_ttl)-1) > 0){

                ip_hdr->ip_ttl--;
                ip_hdr->ip_sum = cksum(packet + sizeof(struct sr_ethernet_hdr), sizeof(struct sr_ip_hdr));
                memcpy(&(e_hdr->ether_dhost), mac_dst, ETHER_ADDR_LEN * sizeof (uint8_t));

                printf("-------------------------------------------\n");
                print_hdr_ip((bufARR + sizeof(struct sr_ethernet_hdr)));
                sr_send_packet(sr,bufARR,pkts->len,pkts->iface);
              }

              else{
                /*send time exceeded message*/
                struct sr_ethernet_hdr* ehdr_sender = (struct sr_ethernet_hdr*)packet;
                
                int lenI = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
                uint8_t *bufTE = malloc(lenI);

                struct sr_icmp_t3_hdr* icmp_res = (struct sr_icmp_t3_hdr*)(bufTE + sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_ip_hdr));
                struct sr_ip_hdr* ip_res = (struct sr_ip_hdr*)(bufTE + sizeof(struct sr_ethernet_hdr));
                struct sr_ethernet_hdr* ehdr_response = (struct sr_ethernet_hdr*)bufTE;

                /* do the echo reply here*/

                /* BUILDING ETHER HEADER*/
                memcpy(&(ehdr_response->ether_shost), &(if_walker->addr), ETHER_ADDR_LEN * sizeof (uint8_t));
                memcpy(&(ehdr_response->ether_dhost), &(ehdr_sender->ether_shost), ETHER_ADDR_LEN * sizeof (uint8_t));
                ehdr_response->ether_type = (uint16_t)htons(ethertype_ip);
                /* BUILDING IP HEADER*/
                ip_res->ip_tos = 0;			/* type of service */
                ip_res->ip_len = sizeof(struct sr_ip_hdr);
                ip_res->ip_ttl = 255;			/* time to live */
                ip_res->ip_p = (uint8_t)htons(ip_protocol_icmp);			
                ip_res->ip_src=(uint32_t)if_walker->ip; 
                ip_res->ip_dst = (uint32_t)ip_hdr->ip_src;
                ip_res->ip_sum = cksum((bufTE +  sizeof(struct sr_ethernet_hdr)), sizeof(struct sr_ip_hdr));
                
                /* BUILDING ICMP HEADER*/
                icmp_res->icmp_type = 11;
                icmp_res->icmp_code = 0;
                memcpy(&(icmp_res->data), ip_hdr, ip_hdr->ip_len * sizeof (uint8_t));
                memcpy(&(icmp_res->data[(ip_hdr->ip_len)]), (bufTE + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)), (8 * sizeof(uint8_t)));
                icmp_res->icmp_sum = cksum((bufTE +  sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)), sizeof(struct sr_icmp_t3_hdr));

                sr_send_packet(sr,bufTE,lenI,if_walker->name);
                
                free(bufTE);
                
              }
            }
            pkts = pkts->next;
          }
          sr_arpreq_destroy(cache, req);
        }
      }
    }
  }

  /* ip frame handling*/
  else if (etype == ethertype_ip){

    printf("its an IP packet!\n");
    printf("-------------------------------------------\n");

    print_hdr_ip(packet + sizeof(struct sr_ethernet_hdr));
        
    struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    
    uint16_t ck = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;

    uint16_t cs = cksum((packet + sizeof(struct sr_ethernet_hdr)), sizeof(struct sr_ip_hdr));

    if( cs != ck){
      printf("\n");
      fprintf(stderr, "\tchecksum calculated: %d\n", cs);
      fprintf(stderr,"erro with checksum\n");
    }

    else{

      ip_hdr->ip_sum = ck;

      struct sr_if* if_walker = sr->if_list;
      int flag = 0;

      while(if_walker){
        if(if_walker->ip == ip_hdr->ip_dst){ 
            flag = 1;
            break; 
        }
        if_walker = if_walker->next;
      }

      /*its for us*/
      if(flag==1){

        uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));

        if(ip_proto == ip_protocol_icmp){

          printf("its an ICMP packet for us!\n");
          struct sr_icmp_hdr* icmp_hdr = (struct sr_icmp_hdr*)(packet +  sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

          if(cksum((packet +  sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)), len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr)) == icmp_hdr->icmp_sum){

            /* if its an echo request*/
            if(icmp_hdr->icmp_type == 0){
              printf("its an echo request!\n");
              struct sr_ethernet_hdr* ehdr_sender = (struct sr_ethernet_hdr*)packet;
              
              int lenI = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr);
              uint8_t *buf = malloc(lenI);

              struct sr_icmp_hdr* icmp_res = (struct sr_icmp_hdr*)(buf + sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_ip_hdr));
              struct sr_ip_hdr* ip_res = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
              struct sr_ethernet_hdr* ehdr_response = (struct sr_ethernet_hdr*)buf;

              /* do the echo reply here*/

              /* BUILDING ETHER HEADER*/
              memcpy(&(ehdr_response->ether_shost), &(if_walker->addr), ETHER_ADDR_LEN * sizeof (uint8_t));
              memcpy(&(ehdr_response->ether_dhost), &(ehdr_sender->ether_shost), ETHER_ADDR_LEN * sizeof (uint8_t));
              ehdr_response->ether_type = (uint16_t)htons(ethertype_ip);
              /* BUILDING IP HEADER*/
              ip_res->ip_tos = 0;			/* type of service */
              ip_res->ip_len = sizeof(struct sr_ip_hdr);
              ip_res->ip_ttl = 255;			/* time to live */
              ip_res->ip_p = htons(ip_protocol_icmp);			
              ip_res->ip_src=(uint32_t)if_walker->ip; 
              ip_res->ip_dst = (uint32_t)ip_hdr->ip_src;
              ip_res->ip_sum = cksum((buf +  sizeof(struct sr_ethernet_hdr)), lenI - sizeof(struct sr_ethernet_hdr));
              
              /* BUILDING ICMP HEADER*/
              icmp_res->icmp_type = 0;
              icmp_res->icmp_sum = cksum((buf +  sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)),  sizeof(struct sr_icmp_hdr));

              sr_send_packet(sr,buf,lenI,if_walker->name);
              
              free(buf);
            }
          }
            /*/check sum didn't pass*/
        }

        else if(ip_proto == htons(0x0006) || ip_proto == htons(0x0011)){
          printf("its TCP or UDP!\n");

          struct sr_ethernet_hdr* ehdr_sender = (struct sr_ethernet_hdr*)packet;
          
          int lenI = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
          uint8_t *buf = malloc(lenI);

          struct sr_icmp_t3_hdr* icmp_res = (struct sr_icmp_t3_hdr*)(buf + sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_icmp_t3_hdr));
          struct sr_ip_hdr* ip_res = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
          struct sr_ethernet_hdr* ehdr_response = (struct sr_ethernet_hdr*)buf;

          /* BUILDING ETHER HEADER*/
          memcpy(&(ehdr_response->ether_shost), &(if_walker->addr), ETHER_ADDR_LEN * sizeof (uint8_t));
          memcpy(&(ehdr_response->ether_dhost), &(ehdr_sender->ether_shost), ETHER_ADDR_LEN * sizeof (uint8_t));
          ehdr_response->ether_type = (uint16_t)htons(ethertype_ip);
          /* BUILDING IP HEADER*/
          ip_res->ip_tos = 0;
          ip_res->ip_len = sizeof(struct sr_ip_hdr);
          ip_res->ip_ttl = 255;
          ip_res->ip_p = htons(ip_protocol_icmp);			
          ip_res->ip_src=(uint32_t)if_walker->ip; 
          ip_res->ip_dst = (uint32_t)ip_hdr->ip_src;
          ip_res->ip_sum = cksum((buf +  sizeof(struct sr_ethernet_hdr)), lenI - sizeof(struct sr_ethernet_hdr));
          
          /* BUILDING ICMP HEADER*/
          icmp_res->icmp_type = 3;
          icmp_res->icmp_code = 3;
          memcpy(&(icmp_res->data), ip_hdr, ip_hdr->ip_len * sizeof (uint8_t));
          memcpy(&(icmp_res->data[(ip_hdr->ip_len)]), (buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)), (8 * sizeof(uint8_t)));
          icmp_res->icmp_sum = cksum((buf +  sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)),  sizeof(struct sr_icmp_t3_hdr));

          sr_send_packet(sr,buf,lenI,if_walker->name);
          
          free(buf);
          
        }
      }
      /*NOT FOR US*/
      else{
        /*check lpm then check cache for mapping*/

        struct sr_rt* rt = (struct sr_rt*)(sr->routing_table);
        struct sr_rt* lpm = 0;
        unsigned long lpm_len = 0;

        while(rt){
          if (((rt->dest.s_addr & rt->mask.s_addr) == ((unsigned long)(ip_hdr->ip_dst)& rt->mask.s_addr)) && (lpm_len <= rt->mask.s_addr)) {
            lpm_len = rt->mask.s_addr;
            lpm = rt;
          }

          rt = rt->next;
        }

        if(lpm == 0){
          /*icmp net unreachable*/
          printf("net unreachable\n");
          
          struct sr_ethernet_hdr* ehdr_sender = (struct sr_ethernet_hdr*)packet;
          
          int lenI = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
          uint8_t *buf = malloc(lenI);

          struct sr_icmp_t3_hdr* icmp_res = (struct sr_icmp_t3_hdr*)(buf + sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_ip_hdr));
          struct sr_ip_hdr* ip_res = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
          struct sr_ethernet_hdr* ehdr_response = (struct sr_ethernet_hdr*)buf;

          /* BUILDING ETHER HEADER*/
          memcpy(&(ehdr_response->ether_shost), &(if_walker->addr), ETHER_ADDR_LEN * sizeof (uint8_t));
          memcpy(&(ehdr_response->ether_dhost), &(ehdr_sender->ether_shost), ETHER_ADDR_LEN * sizeof (uint8_t));
          ehdr_response->ether_type = (uint16_t)htons(ethertype_ip);

          /* BUILDING IP HEADER*/
          ip_res->ip_tos = 0;
          ip_res->ip_len = sizeof(struct sr_ip_hdr);
          ip_res->ip_ttl = 255;
          ip_res->ip_p = htons(ip_protocol_icmp);			
          ip_res->ip_src=(uint32_t)if_walker->ip; 
          ip_res->ip_dst = (uint32_t)ip_hdr->ip_src;
          ip_res->ip_sum = cksum((buf +  sizeof(struct sr_ethernet_hdr)), lenI - sizeof(struct sr_ethernet_hdr));
          
          /* BUILDING ICMP HEADER*/
          icmp_res->icmp_type = 3;
          icmp_res->icmp_code = 0;
          memcpy(&(icmp_res->data), ip_hdr, ip_hdr->ip_len * sizeof (uint8_t));
          memcpy(&(icmp_res->data[(ip_hdr->ip_len)]), (buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)), (8 * sizeof(uint8_t)));
          icmp_res->icmp_sum = cksum((buf +  sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)),  sizeof(struct sr_icmp_t3_hdr));

          sr_send_packet(sr,buf,lenI,if_walker->name);
          
          free(buf);
        }

        /*must forward the packet*/
        else{
          struct sr_arpentry * entry_lookup = sr_arpcache_lookup(&(sr->cache), (uint32_t)(lpm->gw.s_addr));

          if(entry_lookup){
            printf("forward packet\n");


            struct sr_ethernet_hdr* ehdr_response = (struct sr_ethernet_hdr*)(packet);            

            if(((ip_hdr->ip_ttl)-1) > 0){

              ip_hdr->ip_ttl--;
              ip_hdr->ip_sum = cksum(packet + sizeof(struct sr_ethernet_hdr), sizeof(struct sr_ip_hdr));
              memcpy(&(ehdr_response->ether_dhost), (entry_lookup->mac), ETHER_ADDR_LEN * sizeof (uint8_t));

              printf("-------------------------------------------\n");
              print_hdr_ip((packet + sizeof(struct sr_ethernet_hdr)));

              sr_send_packet(sr,packet,len,interface);
            }

            else{
              /*send time exceeded message*/
              struct sr_ethernet_hdr* ehdr_sender = (struct sr_ethernet_hdr*)packet;
              
              int lenI = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
              uint8_t *bufTE = malloc(lenI);

              struct sr_icmp_t3_hdr* icmp_res = (struct sr_icmp_t3_hdr*)(bufTE + sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_ip_hdr));
              struct sr_ip_hdr* ip_res = (struct sr_ip_hdr*)(bufTE + sizeof(struct sr_ethernet_hdr));
              struct sr_ethernet_hdr* ehdr_response = (struct sr_ethernet_hdr*)bufTE;

              /* do the echo reply here*/

              /* BUILDING ETHER HEADER*/
              memcpy(&(ehdr_response->ether_shost), &(if_walker->addr), ETHER_ADDR_LEN * sizeof (uint8_t));
              memcpy(&(ehdr_response->ether_dhost), &(ehdr_sender->ether_shost), ETHER_ADDR_LEN * sizeof (uint8_t));
              ehdr_response->ether_type = (uint16_t)htons(ethertype_ip);
              /* BUILDING IP HEADER*/
              ip_res->ip_tos = 0;			/* type of service */
              ip_res->ip_len = sizeof(struct sr_ip_hdr);
              ip_res->ip_ttl = 255;			/* time to live */
              ip_res->ip_p = (uint8_t)htons(ip_protocol_icmp);			
              ip_res->ip_src=(uint32_t)if_walker->ip; 
              ip_res->ip_dst = (uint32_t)ip_hdr->ip_src;
              ip_res->ip_sum = cksum((bufTE +  sizeof(struct sr_ethernet_hdr)), sizeof(struct sr_ip_hdr));
              
              /* BUILDING ICMP HEADER*/
              icmp_res->icmp_type = 11;
              icmp_res->icmp_code = 0;
              memcpy(&(icmp_res->data), ip_hdr, ip_hdr->ip_len * sizeof (uint8_t));
              memcpy(&(icmp_res->data[(ip_hdr->ip_len)]), (bufTE + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)), (8 * sizeof(uint8_t)));
              icmp_res->icmp_sum = cksum((bufTE +  sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)), sizeof(struct sr_icmp_t3_hdr));

              sr_send_packet(sr,bufTE,lenI,if_walker->name);
              
              free(bufTE);
              
            }

            free(entry_lookup);
          }
          else{
            /*send arp request*/

            struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet , len ,interface);

            if(req){
              handle_arpreq(req);
            }
          }
        }
      }
    }
  }
}/* end sr_ForwardPacket */

