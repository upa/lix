#define N 0x80000000
#define L 0x40000000
#define E 0x20000000
#define V 0x10000000
#define I 0x8000000
#define NONCE_MASK 0xFFFFFF

struct lisphdr {
	uint32_t	flags;
	uint32_t	loc_status;
};

/*
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8                    priority:4,
                                version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u8                    version:4,
                                priority:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8                    flow_lbl[3];

        __be16                  payload_len;
        __u8                    nexthdr;
        __u8                    hop_limit;

        struct  in6_addr        saddr;
        struct  in6_addr        daddr;
};
*/


struct ipv6_itr_header {
	struct ipv6hdr	ip6;
	struct udphdr	udp;
	struct lisphdr	lisp;
};

struct ipv4_itr_header {
	struct iphdr	ip;
	struct udphdr	udp;
	struct lisphdr	lisp;
};

struct sk_buff *ipv6_encap_packet_itr(void *buf, int size, void *saddr, void *daddr);
struct sk_buff *ipv4_encap_packet_itr(void *buf, int size, void *saddr, void *daddr);
