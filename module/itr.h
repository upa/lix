unsigned int ipv4_itr_process_packet(struct iphdr *iph, int data_len, const struct net_device *in);
unsigned int ipv4_itr_input_wrapper(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
unsigned int ipv6_itr_process_packet(struct ipv6hdr *ip6h, int data_len, const struct net_device *in);
unsigned int ipv6_itr_input_wrapper(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
