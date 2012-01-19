#include <linux/sched.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <linux/socket.h>

#include "main.h"
#include "netlink.h"
#include "route.h"

void nl_send_request(int af, char *daddr){
	struct sk_buff * skb;
	struct nlmsghdr *nlh = NULL;
	struct netlink_request *req;

        skb = alloc_skb(NLMSG_SPACE(sizeof(struct netlink_request)), GFP_ATOMIC);
        skb_put(skb, NLMSG_SPACE(sizeof(struct netlink_request)));

        nlh = (struct nlmsghdr *)skb->data;
        nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct netlink_request));
        nlh->nlmsg_pid = 0;
        nlh->nlmsg_flags = 0;

        req = (struct netlink_request *)NLMSG_DATA(nlh);

        req->dest_af = htonl(af);
        if(af == 1){
                memset(req->daddr, 0, 16);
                memcpy(req->daddr, daddr, 4);
		//printk("request address = %pI4\n", daddr);
        }else if(af == 2){
                memcpy(req->daddr, daddr, 16);
        }


        NETLINK_CB(skb).pid = 0; //from kernel
	NETLINK_CB(skb).dst_group = NETLINK_GROUP; //multicast for group 1

	netlink_broadcast(nl_sk, skb, NETLINK_CB(skb).pid, NETLINK_CB(skb).dst_group, GFP_KERNEL);
	return;
}

void nl_receive_result(struct sk_buff *skb){
	struct nlmsghdr *nlh = NULL;
	struct netlink_result *res;

	wake_up_interruptible(nl_sk->sk_sleep);

	if(skb == NULL) {
		printk(KERN_INFO "NULL skb.\n");
		return;
	}

	nlh = (struct nlmsghdr *)skb->data;
	res = (struct netlink_result *)NLMSG_DATA(nlh);

	if(ntohl(res->operation) == ROUTE_REGIST){
		if(ntohl(res->af) == 1){
       	        	spin_lock(&route4);
                	regist_prefix(&ipv4_start, res->eid, ntohl(res->prefix), res->rloc, ntohl(res->rloc_af));
                	spin_unlock(&route4);
		} else if(ntohl(res->af) == 2) {
                	spin_lock(&route6);
                	regist_prefix(&ipv6_start, res->eid, ntohl(res->prefix), res->rloc, ntohl(res->rloc_af));
                	spin_unlock(&route6);
		}

	}else if(ntohl(res->operation) == ROUTE_DELETE){
		if(ntohl(res->af) == 1){
       	        	spin_lock(&route4);
                	delete_prefix(&ipv4_start, res->eid, ntohl(res->prefix));
                	spin_unlock(&route4);
		} else if(ntohl(res->af) == 2) {
                	spin_lock(&route6);
                	delete_prefix(&ipv6_start, res->eid, ntohl(res->prefix));
                	spin_unlock(&route6);
		}

	}

	return;
}

