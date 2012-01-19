#define NETDEV_NAME "rloc0"

#define NETLINK_LISP 17
#define NETLINK_GROUP 1
#define MTU 1500

extern struct sock *nl_sk;
extern struct net_device *rloc_dev;
extern spinlock_t route4;
extern spinlock_t route6;
extern struct route_entry ipv4_start;
extern struct route_entry ipv6_start;

