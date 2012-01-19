#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/inetdevice.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/ip6_route.h>

#include <net/ipv6.h>
#include <linux/version.h>


#include "main.h"
#include "netdev.h"
#include "netlink.h"
#include "etr.h"
#include "itr.h"
#include "route.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yukito Ueno");
MODULE_DESCRIPTION("Linux LISP implementation");

struct net_device	*rloc_dev;

struct sock *nl_sk = NULL;

spinlock_t route4 = SPIN_LOCK_UNLOCKED;
spinlock_t route6 = SPIN_LOCK_UNLOCKED;

struct route_entry ipv6_start;
struct route_entry ipv4_start;

static int __init lisp_init(void);
static void __exit lisp_exit(void);

static struct nf_hook_ops lisp_etr_nf_hook4 __read_mostly =
{
        .hook           = ipv4_etr_input_wrapper,
        .owner          = THIS_MODULE,
        .pf             = NFPROTO_IPV4,
        .hooknum        = NF_INET_LOCAL_IN,
        .priority       = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops lisp_itr_nf_hook4 __read_mostly =
{
        .hook           = ipv4_itr_input_wrapper,
        .owner          = THIS_MODULE,
        .pf             = NFPROTO_IPV4,
        .hooknum        = NF_INET_FORWARD,
        .priority       = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops lisp_etr_nf_hook6 __read_mostly =
{
        .hook           = ipv6_etr_input_wrapper,
        .owner          = THIS_MODULE,
        .pf             = NFPROTO_IPV6,
        .hooknum        = NF_INET_LOCAL_IN,
        .priority       = NF_IP6_PRI_FIRST,
};

static struct nf_hook_ops lisp_itr_nf_hook6 __read_mostly =
{
        .hook           = ipv6_itr_input_wrapper,
        .owner          = THIS_MODULE,
        .pf             = NFPROTO_IPV6,
        .hooknum        = NF_INET_FORWARD,
        .priority       = NF_IP6_PRI_FIRST,
};

static int __init lisp_init(void){
	int ret;
	printk(KERN_INFO "lisp: init:  module loaded.\n");

	memset(&ipv4_start, 0, sizeof(struct route_entry));
	memset(&ipv6_start, 0, sizeof(struct route_entry));

	ret = nf_register_hook(&lisp_etr_nf_hook4);
	if (ret) {
		printk(KERN_ERR "lisp: init: Unable to register IPv4 ETR netfilter hooks\n");
		return -1;
	}

        ret = nf_register_hook(&lisp_itr_nf_hook4);
        if (ret) {
		printk(KERN_ERR "lisp: init: Unable to register IPv4 ITR netfilter hooks\n");
                return -1;
        }

        ret = nf_register_hook(&lisp_etr_nf_hook6);
        if (ret) {
		printk(KERN_ERR "lisp: init: Unable to register IPv6 ETR netfilter hooks\n");
                return -1;
        }

        ret = nf_register_hook(&lisp_itr_nf_hook6);
        if (ret) {
		printk(KERN_ERR "lisp: init: Unable to register IPv6 ITR netfilter hooks\n");
                return -1;
        }

	/* netdev is created here */
	ret = netdev_create(&rloc_dev);
	if(ret){
		printk(KERN_ERR "lisp: init: Unable to create net device\n");
		return -1;
	}

        nl_sk = netlink_kernel_create(&init_net, NETLINK_LISP, NETLINK_GROUP, nl_receive_result, NULL, THIS_MODULE);
        if(nl_sk == NULL){
		printk(KERN_ERR "lisp: init: Unable to create netlink socket.\n");
                return -1;
        }

	return 0;

}

static void __exit lisp_exit(void){
	netdev_destroy(rloc_dev);

	nf_unregister_hook(&lisp_etr_nf_hook4);
	nf_unregister_hook(&lisp_itr_nf_hook4);
        nf_unregister_hook(&lisp_etr_nf_hook6);
        nf_unregister_hook(&lisp_itr_nf_hook6);

        if(nl_sk != NULL){
		sock_release(nl_sk->sk_socket);
        }

	printk(KERN_INFO "lisp: exit: module unloaded.\n");
}

module_init(lisp_init);
module_exit(lisp_exit);
