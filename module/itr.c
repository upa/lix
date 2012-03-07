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
#include <linux/icmpv6.h>
#include <linux/version.h>
#include <net/addrconf.h>


#include "main.h"
#include "itr.h"
#include "route.h"
#include "encapsulate.h"
#include "mtu.h"
#include "utils.h"
#include "netlink.h"

unsigned int ipv4_itr_process_packet(struct iphdr *iph, int data_len, const struct net_device *in){
	char nexthop[16];
	char accept[16];
	char drop[16];
	char rloc[16];
	int match_len;
	int af = 0;

	memset(nexthop, 0, 16);
	memset(accept, 0, 16);
	memset(drop, 0xff, 16);

	spin_lock_bh(&route4);
	match_len = match_dst(&ipv4_start, (char *)&(iph->daddr), nexthop, &af);
	spin_unlock_bh(&route4);

        if((af == 2) && (data_len > MTU - 56)){
                ipv4_fragment_packet((char *)iph, data_len, MTU - 56, in);
                return NF_DROP;
        }else if((af == 1) && (data_len > MTU - 36)){
                ipv4_fragment_packet((char *)iph, data_len, MTU - 36, in);
                return NF_DROP;
        }

	if(match_len > 0){
		if(!memcmp(nexthop, accept, 16)){
			return NF_ACCEPT;
                }else if(!memcmp(nexthop, drop, 16)){
                        /* DROP */
			return NF_DROP;
		}else{
			if(af == 2){
				struct sk_buff *packet = NULL;		

				/* encapsulate in ipv6 packet */
				ipv6_dev_get_saddr(&init_net, (struct net_device *)rloc_dev, (const struct in6_addr *)nexthop, 0, (struct in6_addr *)rloc);
				packet = ipv6_encap_packet_itr((char *)iph, data_len, rloc, nexthop);

				/* forward */
				ipv6_inject_packet(packet);

				return NF_DROP;
			}else if(af == 1){
				struct sk_buff *packet = NULL;

				/* encapsulate in ipv4 packet */
				*((unsigned *)rloc) = inet_select_addr(rloc_dev, 0, 0);
				packet = ipv4_encap_packet_itr((char *)iph, data_len, rloc, nexthop);

                                /* forward */
				ipv4_inject_packet(packet);

				return NF_DROP;
			}
		}
	}else{
		/* register temporary drop table */
		spin_lock_bh(&route4);
		regist_prefix(&ipv4_start, (char *)&(iph->daddr), 32, drop, 0);
		spin_unlock_bh(&route4);

		/* instead of enqueue, request user land daemon to send Map-request */
		nl_send_request(1, (char *)&(iph->daddr));

		return NF_DROP;
	}

	return 0;
}

unsigned int ipv6_itr_process_packet(struct ipv6hdr *ip6h, int data_len, const struct net_device *in){
	char nexthop[16];
	char accept[16];
	char drop[16];
	char rloc[16];
	int match_len;
	int af = 0;

	memset(nexthop, 0, 16);
	memset(accept, 0, 16);
	memset(drop, 0xff, 16);

	spin_lock_bh(&route6);
	match_len = match_dst(&ipv6_start, (char *)&(ip6h->daddr), nexthop, &af);
	spin_unlock_bh(&route6);

        if((af == 2) && (data_len > MTU - 56)){
                ipv6_return_icmp((char *)ip6h, data_len, MTU - 56, in);
                return NF_DROP;
        }else if((af == 1) && (data_len > MTU - 36)){
                ipv6_return_icmp((char *)ip6h, data_len, MTU - 36, in);
                return NF_DROP;
        }

	if(match_len > 0){
		if(!memcmp(nexthop, accept, 16)){
			return NF_ACCEPT;
                }else if(!memcmp(nexthop, drop, 16)){
                        /* DROP */
			return NF_DROP;
		}else{
			if(af == 2){
				struct sk_buff *packet = NULL;		

				/* encapsulate in ipv6 packet */
				ipv6_dev_get_saddr(&init_net, (struct net_device *)rloc_dev, (const struct in6_addr *)nexthop, 0, (struct in6_addr *)rloc);
				packet = ipv6_encap_packet_itr((char *)ip6h, data_len, rloc, nexthop);

				/* forward */
				ipv6_inject_packet(packet);

				return NF_DROP;
			}else if(af == 1){
				struct sk_buff *packet = NULL;

				/* encapsulate in ipv4 packet */
				*((unsigned *)rloc) = inet_select_addr(rloc_dev, 0, 0);
				packet = ipv4_encap_packet_itr((char *)ip6h, data_len, rloc, nexthop);

                                /* forward */
				ipv4_inject_packet(packet);

				return NF_DROP;
			}
		}
	}else{
		/* register temporary drop table */
		spin_lock_bh(&route6);
		regist_prefix(&ipv6_start, (char *)&(ip6h->daddr), 128, drop, 0);
		spin_unlock_bh(&route6);

		/* instead of enqueue, request user land daemon to send Map-request */
		nl_send_request(2, (char *)&(ip6h->daddr));

		return NF_DROP;
	}

	return 0;
}

unsigned int ipv4_itr_input_wrapper(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	unsigned int ret = NF_ACCEPT;

	if(skb->pkt_type != PACKET_HOST)
		return NF_ACCEPT;

	if (skb_linearize(skb) < 0) {
		return NF_ACCEPT;
	}

	/* for etr packet */
	if(!memcmp(in->name, rloc_dev->name, IFNAMSIZ)){
		return NF_ACCEPT;
	}

	ret = ipv4_itr_process_packet((struct iphdr *)skb->data, skb->len, in);

	return ret;
}

unsigned int ipv6_itr_input_wrapper(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	unsigned int ret = NF_ACCEPT;

	if(skb->pkt_type != PACKET_HOST)
		return NF_ACCEPT;

	if (skb_linearize(skb) < 0) {
		return NF_ACCEPT;
	}

        /* for etr packet */
        if(!memcmp(in->name, rloc_dev->name, IFNAMSIZ)){
                return NF_ACCEPT;
        }

	ret = ipv6_itr_process_packet((struct ipv6hdr *)skb->data, skb->len, in);

	return ret;
}
