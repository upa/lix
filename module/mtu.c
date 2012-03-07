#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>

#include "main.h"
#include "utils.h"
#include "mtu.h"
#include "itr.h"

void ipv4_fragment_packet(char *frame, int data_len, int limit, const struct net_device *in){
	struct iphdr *ip;
	int payload_len;
	int size;
	char *packet;
	struct iphdr *hdr;
	int i = 0, s, j, flag = 0;

	ip = (struct iphdr *)frame;

	/* if DF bit is set or not */
	if(ip->frag_off & htons(0x4000)){
		ipv4_return_icmp(frame, data_len, limit, in);
		return;
	}

	/* calculate number of fragmented packets */

        payload_len = data_len - sizeof(struct iphdr);
	s = payload_len;
	while(s > 0){
		s -= ((limit - 20) / 8) * 8;
		i++;
	}


	/* process each fragmented packet */
	s = payload_len;
	for(j = 0; j < i; j++){
		if(s <= (((limit - 20) / 8) * 8)){
			size = s;
			flag = 1;
		}else{
			size = ((limit - 20) / 8) * 8;
		}

		packet = kmalloc(size + sizeof(struct iphdr), GFP_ATOMIC);
		hdr = (struct iphdr *)packet;

		memset(packet, 0, size + sizeof(struct iphdr));
		memcpy(packet, frame, sizeof(struct iphdr));

		hdr->frag_off = htons((payload_len - s) / 8);
		if(!flag){
			hdr->frag_off |= htons(0x2000);
		}

		hdr->tot_len = htons(size + sizeof(struct iphdr));

		memcpy(packet + sizeof(struct iphdr), frame + sizeof(struct iphdr) + (payload_len - s), size);

		hdr->check = 0;
		hdr->check = ipv4_checksum((unsigned short *)packet, sizeof(struct iphdr));

		ipv4_itr_process_packet((struct iphdr *)packet, size + sizeof(struct iphdr), in);
		s -= size;
	}

}

void ipv4_return_icmp(char *frame, int data_len, int limit, const struct net_device *in){
	struct iphdr *from;
	struct ip_icmp *packet;
	struct sk_buff *skb;
	static int identification;

	skb = alloc_skb(LL_MAX_HEADER + sizeof(struct ip_icmp), GFP_ATOMIC);
	skb_reserve(skb, LL_MAX_HEADER);
	skb_put(skb, sizeof(struct ip_icmp));
	skb_reset_network_header(skb);
	packet = (struct ip_icmp *)skb->data;

	from = (struct iphdr *)frame;
	memset(packet, 0, sizeof(struct ip_icmp));

	packet->ip.ihl = 5;
	packet->ip.version = 4;
	packet->ip.tot_len = htons(sizeof(struct ip_icmp));
	packet->ip.id = htons(++identification);
	packet->ip.ttl = 64;
	packet->ip.protocol = 1;

	*((unsigned *)&(packet->ip.saddr)) = inet_select_addr(in, 0, 0);
	memcpy(&(packet->ip.daddr), &(from->saddr), 4);

	packet->ip.check = ipv4_checksum((unsigned short *)packet, sizeof(struct iphdr));

	packet->icmp.type = 3;
	packet->icmp.code = 4;
	packet->icmp.un.frag.mtu = htons(limit);
	memcpy(packet->data, frame, 64);
	packet->icmp.checksum = ipv4_checksum((unsigned short *)&(packet->icmp), sizeof(struct icmphdr) + 64);

	ipv4_inject_packet(skb);
}

void ipv6_return_icmp(char *frame, int data_len, int limit, const struct net_device *in){
	struct ipv6hdr *from;
	struct ip6_icmp *packet;
	struct sk_buff *skb;

	skb = alloc_skb(LL_MAX_HEADER + sizeof(struct ip6_icmp), GFP_ATOMIC);
	skb_reserve(skb, LL_MAX_HEADER);
	skb_put(skb, sizeof(struct ip6_icmp));
	skb_reset_network_header(skb);
	packet = (struct ip6_icmp *)skb->data;

	from = (struct ipv6hdr *)frame;
	memset(packet, 0, sizeof(struct ip6_icmp));

	packet->ip6.version = 6;
	packet->ip6.payload_len = htons(sizeof(struct ip6_icmp) - sizeof(struct ipv6hdr));
	packet->ip6.nexthdr = 58;
	packet->ip6.hop_limit = 64;

	memcpy(&(packet->ip6.daddr), &(from->saddr), 16);
	ipv6_dev_get_saddr(&init_net, (struct net_device *)in, (const struct in6_addr *)&(packet->ip6.daddr), 0, &(packet->ip6.saddr));

	packet->icmp6.icmp6_type = 2;
	packet->icmp6.icmp6_code = 0;
	packet->icmp6.icmp6_mtu = htonl(limit);
	memcpy(packet->data, frame, 64);
	packet->icmp6.icmp6_cksum = icmp6_checksum(&(packet->ip6), (unsigned short *)&(packet->icmp6), sizeof(struct ip6_icmp) - sizeof(struct ipv6hdr));

	ipv6_inject_packet(skb);
}
























