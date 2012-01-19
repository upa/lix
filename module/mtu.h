
struct ip_icmp {
	struct iphdr		ip;
	struct icmphdr		icmp;
	char			data[64];
};

struct ip6_icmp {
	struct ipv6hdr		ip6;
	struct icmp6hdr		icmp6;
	char			data[64];
};



void ipv4_fragment_packet(char *frame, int data_len, int limit, const struct net_device *in);
void ipv6_return_icmp(char *frame, int data_len, int limit, const struct net_device *in);
void ipv4_return_icmp(char *frame, int data_len, int limit, const struct net_device *in);

