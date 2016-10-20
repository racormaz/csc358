#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/


void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req){
    time_t curtime = time(NULL);

    if(difftime(curtime,req->sent) > 1.0){
        if(req->times_sent >= 5){
            /*send icmp to all pkts waiting on this req*/

            struct sr_packet *p_walker = (struct sr_packet*)(req->packets);

            while(p_walker->next){

                uint8_t* packet = p_walker->buf;
                
                struct sr_if* if_walker = sr_get_interface(sr, p_walker->iface);

                struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
                struct sr_ethernet_hdr* ehdr_sender = (struct sr_ethernet_hdr*)packet;
          
                int lenI = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);

                uint8_t *buf = malloc(lenI);

                struct sr_icmp_t3_hdr* icmp_res = (struct sr_icmp_t3_hdr*)(buf + sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_ip_hdr));
                struct sr_ip_hdr* ip_res = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
                struct sr_ethernet_hdr* ehdr_response = (struct sr_ethernet_hdr*)buf;

                /* BUILDING ETHER HEADER*/
                memcpy(&(ehdr_response->ether_shost), &(if_walker->addr), ETHER_ADDR_LEN * sizeof (uint8_t));
                memcpy(&(ehdr_response->ether_dhost), &(ehdr_sender->ether_shost), ETHER_ADDR_LEN * sizeof (uint8_t));

                /* BUILDING IP HEADER*/
                ip_res->ip_tos = 0;
                ip_res->ip_len = sizeof(struct sr_ip_hdr);
                ip_res->ip_ttl = 65;
                ip_res->ip_p = htons(ip_protocol_icmp);			
                ip_res->ip_src=(uint32_t)if_walker->ip; 
                ip_res->ip_dst = (uint32_t)ip_hdr->ip_src;
                ip_res->ip_sum = cksum((buf +  sizeof(struct sr_ethernet_hdr)), sizeof(struct sr_ip_hdr));
                
                /* BUILDING ICMP HEADER*/
                icmp_res->icmp_type = 3;
                icmp_res->icmp_code = 1;
                memcpy(&(icmp_res->data), ip_hdr, ip_hdr->ip_len * sizeof (uint8_t));
                memcpy(&(icmp_res->data[(ip_hdr->ip_len)]), (buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)), ((ip_hdr->ip_len) * sizeof(uint8_t)));
                icmp_res->icmp_sum = cksum((buf +  sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)),  sizeof(struct sr_icmp_hdr));

                sr_send_packet(sr,buf,lenI,if_walker->name);
                
                free(buf);

                p_walker = p_walker->next;
            }

            sr_arpreq_destroy(&(sr->cache), req);
        }

        else{

            /*ARP Request*/

            struct sr_if* srif = sr->if_list;

            int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
            
            uint8_t *buf = malloc(len);

            struct sr_arp_hdr* arp_response = (struct sr_arp_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
            struct sr_ethernet_hdr* ehdr_response = (struct sr_ethernet_hdr*)buf;

            arp_response->ar_hrd = htons(arp_hrd_ethernet);
            arp_response->ar_pro = htons(ethertype_ip);
            arp_response->ar_hln = 6;
            arp_response->ar_pln = 4;
            arp_response->ar_op = htons(arp_op_request);

            memset(&(arp_response->ar_tha), 0x00,ETHER_ADDR_LEN * sizeof (char));
            memset(&(ehdr_response->ether_dhost), 0xFF, ETHER_ADDR_LEN * sizeof (uint8_t));

            memcpy(&(arp_response->ar_sha), &(srif->addr), ETHER_ADDR_LEN * sizeof (char));
            memcpy(&(ehdr_response->ether_shost), &(srif->addr), ETHER_ADDR_LEN * sizeof (uint8_t));

            arp_response->ar_tip = (uint32_t)req->ip;
            arp_response->ar_sip = (uint32_t)srif->ip;

            ehdr_response->ether_type = (uint16_t)htons(ethertype_arp);

            printf("send the ARP request\n");

            print_hdr_eth(buf);
            print_hdr_arp(buf + sizeof(struct sr_ethernet_hdr));

            sr_send_packet(sr,buf,len, &(srif->name));

            free(buf);

            req->sent = curtime;
            req->times_sent++;
        }
    }
}


void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */

    struct sr_arpcache cache = sr->cache;

    struct sr_arpreq* req_walker = (struct sr_arpreq*)(cache.requests);
    struct sr_arpreq* req_next;

    while(req_walker->next){
        req_next = req_walker->next;

        handle_arpreq(sr, req_walker);

        req_walker = req_next;
    }


}


/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

