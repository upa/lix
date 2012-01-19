#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/inetdevice.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/ip6_route.h>

#include <net/ipv6.h>
#include <net/addrconf.h>

#include "etr.h"
#include "main.h"
#include "utils.h"

static void ipv4_etr_inject_packet(struct sk_buff *old_skb);
static void ipv6_etr_inject_packet(struct sk_buff *old_skb);
static unsigned int ipv4_etr_input(struct sk_buff *skb);
static unsigned int ipv6_etr_input(struct sk_buff *skb);

static void ipv4_etr_inject_packet(struct sk_buff *old_skb){
        struct sk_buff  *skb;

        skb = alloc_skb(old_skb->len, GFP_ATOMIC);
        if (!skb) {
		printk(KERN_ERR "lisp: etr: Unable to allocate memory for new skbuff structure\n");
                return;
        }

        skb_put(skb, old_skb->len);
        memcpy(skb->data, old_skb->data, old_skb->len);

        skb->protocol = htons(ETH_P_IP);

        skb->dev = rloc_dev;
        rloc_dev->stats.rx_packets++;
        rloc_dev->stats.rx_bytes += skb->len;
        netif_rx(skb);

        return;
}

static void ipv6_etr_inject_packet(struct sk_buff *old_skb){
        struct sk_buff  *skb;

        skb = alloc_skb(old_skb->len, GFP_ATOMIC);
        if (!skb) {
		printk(KERN_ERR "lisp: etr: Unable to allocate memory for new skbuff structure\n");
                return;
        }

        skb_put(skb, old_skb->len);
        memcpy(skb->data, old_skb->data, old_skb->len);

        skb->protocol = htons(ETH_P_IPV6);

        skb->dev = rloc_dev;
        rloc_dev->stats.rx_packets++;
        rloc_dev->stats.rx_bytes += skb->len;
        netif_rx(skb);

        return;
}


static unsigned int ipv4_etr_input(struct sk_buff *skb){
	struct iphdr	*iph = (struct iphdr *)skb->data;
	char rloc[4];
	
	*((unsigned *)rloc) = inet_select_addr(rloc_dev, 0, 0);
	if(iph->protocol == IPPROTO_UDP){
		struct udphdr *udph = (struct udphdr *)(skb->data + sizeof(struct iphdr)); 
		if(ntohs(udph->dest) == 4341){
			*((unsigned *)rloc) = inet_select_addr(rloc_dev, 0, 0);
			if(!memcmp(&(iph->daddr), rloc, 4)){
				skb_pull(skb, sizeof(struct iphdr) + sizeof(struct udphdr) + 8);
				if(return_ip_version(skb->data) == 4){
					ipv4_etr_inject_packet(skb);
				}else{
					ipv6_etr_inject_packet(skb);
				}
				return NF_DROP;
			}else{
				return NF_ACCEPT;
			}
		}else{
			return NF_ACCEPT;
		}
	}else{
		return NF_ACCEPT;
	}
}


static unsigned int ipv6_etr_input(struct sk_buff *skb){
	struct ipv6hdr	*ip6h = (struct ipv6hdr *)skb->data;
	char rloc[16];

	if(ip6h->nexthdr == IPPROTO_UDP){
		struct udphdr *udph = (struct udphdr *)(skb->data + sizeof(struct ipv6hdr)); 
		if(ntohs(udph->dest) == 4341){
			ipv6_dev_get_saddr(&init_net, (struct net_device *)rloc_dev, (const struct in6_addr *)&ip6h->saddr, 0, (struct in6_addr *)rloc);
			if(!memcmp(&(ip6h->daddr), rloc, 16)){
				skb_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct udphdr) + 8);
				if(return_ip_version(skb->data) == 4){
					ipv4_etr_inject_packet(skb);
				}else{
					ipv6_etr_inject_packet(skb);
				}
				return NF_DROP;
			}else{
				return NF_ACCEPT;
			}
		}else{
			return NF_ACCEPT;
		}
	}else{
		return NF_ACCEPT;
	}
}

unsigned int ipv4_etr_input_wrapper(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	unsigned int ret = NF_ACCEPT;

	if(skb->pkt_type != PACKET_HOST)
		return NF_ACCEPT;

	if (skb_linearize(skb) < 0) {
		return NF_ACCEPT;
	}

	ret = ipv4_etr_input(skb);

	return ret;
}



unsigned int ipv6_etr_input_wrapper(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	unsigned int ret = NF_ACCEPT;

	if(skb->pkt_type != PACKET_HOST)
		return NF_ACCEPT;

	if (skb_linearize(skb) < 0) {
		return NF_ACCEPT;
	}

	ret = ipv6_etr_input(skb);

	return ret;
}
