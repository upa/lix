
struct pseudo_ipv6_header{
        char		src_address[16],
			dst_address[16];
        u_int32_t	upper_layer_size;
        u_int8_t	ip6_p_pad[3];
        u_int8_t	ip6_p_nxt;
};

int ipv4_inject_packet(struct sk_buff *skb);
int ipv6_inject_packet(struct sk_buff *skb);
int ipv4_inject_packet_by_dev(struct sk_buff *skb, struct net_device *dev);
int return_ip_version(void *buf);
unsigned short ipv4_checksum(unsigned short *buf, int size);
unsigned short icmp6_checksum(struct ipv6hdr *ip6, unsigned short *payload, int payloadsize);


