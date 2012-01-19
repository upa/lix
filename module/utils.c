#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/version.h>

#include "utils.h"
#include "main.h"


int ipv4_inject_packet(struct sk_buff *skb){
 	int             ret_val;
	struct iphdr    *iph = ip_hdr(skb);
	struct rtable   *rp;
	struct flowi    fl = {
		.oif = 0,
		.mark = 0, // sk->sk_mark,
		.nl_u = {
			.ip4_u =
				{
					.daddr = iph->daddr,
					.saddr = iph->saddr,
					.tos = iph->tos
				}
		},
		.proto = skb->protocol,
		.flags = 0     // or can be FLOWI_FLAG_ANYSRC ??
	};

	ret_val = __ip_route_output_key(&init_net, &rp, &fl);

	if(ret_val) {
		return -1;
	}

	skb->dev = rp->u.dst.dev;
	skb_dst_set(skb, dst_clone(&rp->u.dst));

 	skb->dev->stats.tx_packets++;
	skb->dev->stats.tx_bytes += skb->len;
	dst_output(skb);
	return 0;
}

int ipv6_inject_packet(struct sk_buff *skb){
	struct ipv6hdr  *ip6h = (struct ipv6hdr *)skb->data;
	struct rt6_info *rp;
	struct flowi    fl = {
		.oif = 0,
		.mark = 0, // sk->sk_mark,
		.nl_u = {
			.ip6_u =
				{
					.daddr = ip6h->daddr,
					.saddr = ip6h->saddr,
					.flowlabel = *(unsigned *)ip6h->flow_lbl
				}
		},
		.proto = skb->protocol,
		.flags = 0     // or can be FLOWI_FLAG_ANYSRC ??
	};

	rp = (struct rt6_info *)ip6_route_output(&init_net, NULL, &fl);

	skb->dev = rp->u.dst.dev;
	skb_dst_set(skb, dst_clone(&rp->u.dst));

 	skb->dev->stats.tx_packets++;
	skb->dev->stats.tx_bytes += skb->len;
	dst_output(skb);

	return 0;
}

/* this is not used, but very useful */
int ipv4_inject_packet_by_dev(struct sk_buff *skb, struct net_device *dev){
 	int             ret_val;
	struct iphdr    *iph = (struct iphdr *)skb->data;
	struct rtable   *rp;
	struct flowi    fl = {
		.oif = 0,
		.mark = 0, // sk->sk_mark,
		.nl_u = {
			.ip4_u =
				{
					.daddr = iph->daddr,
					.saddr = iph->saddr,
					.tos = iph->tos
				}
		},
		.proto = skb->protocol,
		.flags = 0     // or can be FLOWI_FLAG_ANYSRC ??
	};

	skb->dev = dev;
	ret_val = __ip_route_output_key(dev_net(skb->dev), &rp, &fl);

	if(ret_val) {
		return -1;
	}

	skb_dst_set(skb, dst_clone(&rp->u.dst));

 	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;
	dst_output(skb);
	return 0;
}

int return_ip_version(void *buf){
	struct iphdr *h;
	
	h = (struct iphdr *)buf;
	
	return h->version;
}

unsigned short ipv4_checksum(unsigned short *buf, int size){
	unsigned long sum = 0;

	while (size > 1) {
		sum += *buf++;
		size -= 2;
	}
	if (size)
		sum += *(u_int8_t *)buf;

	sum  = (sum & 0xffff) + (sum >> 16);	/* add overflow counts */
	sum  = (sum & 0xffff) + (sum >> 16);	/* once again */
	
	return ~sum;
}

unsigned short icmp6_checksum(struct ipv6hdr *ip6, unsigned short *payload, int payloadsize){
        unsigned long sum = 0;

        struct pseudo_ipv6_header p;
        unsigned short *f = (unsigned short *)&p;
        int pseudo_size = sizeof(p);

        memset(&p, 0, sizeof(struct pseudo_ipv6_header));
        memcpy(p.src_address, &(ip6->saddr), 16);
        memcpy(p.dst_address, &(ip6->daddr), 16);
        p.upper_layer_size = htonl(payloadsize);
        p.ip6_p_nxt = 58;

        while (pseudo_size > 1) {
                sum += *f;
                f++;
                pseudo_size -= 2;
        }

        while (payloadsize > 1) {
                sum += *payload;
                payload++;
                payloadsize -= 2;
        }

        if (payloadsize == 1) {
                sum += *(unsigned char *)payload;
        }

        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);

        return ~sum;
}
