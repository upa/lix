#include <linux/types.h>
#include <linux/random.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sctp.h>
#include <linux/icmp.h>
#include <linux/route.h>
#include <net/ip6_route.h>
#include <linux/ipv6.h>

#include "main.h"
#include "utils.h"
#include "encapsulate.h"

static int nonce_for_dataplane(void);
static unsigned short five_tuple_hash(void *buf);

static int nonce_for_dataplane(){
	static int flag;
	static int nonce;

	if(flag == 0){
		get_random_bytes(&nonce, 4);
		nonce &= NONCE_MASK;
	}
	flag = 1;

	return nonce;
}

static unsigned short five_tuple_hash(void *buf){
	int i;
	unsigned short nexthdr;
	unsigned short sum = 0;
	unsigned short *ptr;
	struct ipv6hdr *ip6;
	struct iphdr *ip;
	void *ports;

	switch(return_ip_version(buf)){
		case 6:
			ip6 = (struct ipv6hdr *)buf;
			ptr = (unsigned short *)&(ip6->saddr);
			for(i = 0; i < ((2 * sizeof(struct in6_addr)) / sizeof(unsigned short)); i++){
				sum += *ptr;
				ptr++;
			}
			nexthdr = ntohs(ip6->nexthdr);
			ports = ip6 + 1;
			break;
		case 4:
			ip = (struct iphdr *)buf;
			ptr = (unsigned short *)&(ip->saddr);
                        for(i = 0; i < ((2 * sizeof(struct in_addr)) / sizeof(unsigned short)); i++){
                                sum += *ptr;
                                ptr++;
                        }
			nexthdr = ntohs(ip->protocol);
			ports = ip + 1;
			break;
		default:
			return 0;
			break;
	}

	switch(nexthdr){
		case IPPROTO_UDP:
			ptr = (unsigned short *)ports;
			for(i = 0; i < 2; i++){
				sum += *ptr;
				ptr++;	
			}
			sum += nexthdr;
			break;
		case IPPROTO_TCP:
                        ptr = (unsigned short *)ports;
                        for(i = 0; i < 2; i++){
                                sum += *ptr;
                                ptr++;
                        }
			sum += nexthdr;
			break;
		case IPPROTO_SCTP:
                        ptr = (unsigned short *)ports;
                        for(i = 0; i < 2; i++){
                                sum += *ptr;
                                ptr++;
                        }
			sum += nexthdr;
			break;
		default:
			break;
	}

	return sum;
}

struct sk_buff *ipv6_encap_packet_itr(void *buf, int size, void *saddr, void *daddr){
	struct sk_buff *skb;
	struct ipv6_itr_header *h;
	int packet_len = size + sizeof(struct ipv6_itr_header);

	skb = alloc_skb(LL_MAX_HEADER + packet_len, GFP_ATOMIC);
	skb_reserve(skb, LL_MAX_HEADER);
	skb_put(skb, packet_len);
	skb_reset_network_header(skb);
	skb->protocol = htons(ETH_P_IPV6);

	h = (struct ipv6_itr_header *)skb->data;
	memset(h, 0, sizeof(struct ipv6_itr_header));
	memcpy(skb->data + sizeof(struct ipv6_itr_header), buf, size);

        h->ip6.version = 6;
        h->ip6.payload_len = htons(packet_len - sizeof(struct ipv6hdr));
        h->ip6.nexthdr = 0x11;
        h->ip6.hop_limit = 64;
        memcpy(&(h->ip6.saddr), saddr, 16);
        memcpy(&(h->ip6.daddr), daddr, 16);

	h->udp.source = five_tuple_hash(buf);
	h->udp.dest = htons(4341);
	h->udp.len = htons(size + sizeof(struct udphdr) + sizeof(struct lisphdr));
	h->udp.check = 0;

	h->lisp.flags = htonl(N | L | nonce_for_dataplane());
	h->lisp.loc_status = htonl(1);

	return skb;
}

struct sk_buff *ipv4_encap_packet_itr(void *buf, int size, void *saddr, void *daddr){
	static int identification;
	struct sk_buff *skb;
	struct ipv4_itr_header *h;
	int packet_len = size + sizeof(struct ipv4_itr_header);

	skb = alloc_skb(LL_MAX_HEADER + packet_len, GFP_ATOMIC);
	skb_reserve(skb, LL_MAX_HEADER);
	skb_put(skb, packet_len);
	skb_reset_network_header(skb);
	skb->protocol = htons(ETH_P_IP);

	h = (struct ipv4_itr_header *)skb->data;
	memset(h, 0, sizeof(struct ipv4_itr_header));
	memcpy(skb->data + sizeof(struct ipv4_itr_header), buf, size);

        h->ip.ihl = 5;
        h->ip.version = 4;
        h->ip.tot_len = htons(packet_len);
        h->ip.id = htons(++identification);
        h->ip.ttl = 64;
        h->ip.protocol = 0x11;
	h->ip.frag_off = htons(0x4000);

        memcpy(&(h->ip.saddr), saddr, 4);
        memcpy(&(h->ip.daddr), daddr, 4);

	h->ip.check = 0;
        h->ip.check = ipv4_checksum((unsigned short *)h, sizeof(struct iphdr));

	h->udp.source = five_tuple_hash(buf);
	h->udp.dest = htons(4341);
	h->udp.len = htons(size + sizeof(struct udphdr) + sizeof(struct lisphdr));
	h->udp.check = 0;

	h->lisp.flags = htonl(N | L | nonce_for_dataplane());
	h->lisp.loc_status = htonl(1);

	return skb;
}

