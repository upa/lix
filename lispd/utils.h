#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

struct ipv6_header {
        __u32           FLOW_LABEL : 20,
                        TRAFFIC_CLASS : 8,
                        VERSION : 4,
                        HOP_LIMIT : 8,
                        NEXT_HEADER : 8,
                        PAYLOAD_LEN : 16;
        char            S_ADDRESS[16],
                        D_ADDRESS[16];
};

struct ipv4_header {
         __u32          TOTAL_LEN : 16,
                        TYPE_OF_SERVICE : 8,
                        IHL : 4,
                        VERSION : 4,
                        FRAGMENT_OFFSET : 13,
                        IPFLAGS : 3,
                        IDENTIFICATION : 16,
                        CHECKSUM : 16,
                        PROTOCOL : 8,
                        TTL : 8;
        char            S_ADDRESS[4],
                        D_ADDRESS[4];
};

struct pseudo_ipv6_header{
        char		src_address[16],
			dst_address[16];
        u_int32_t	upper_layer_size;
        u_int8_t	ip6_p_pad[3];
        u_int8_t	ip6_p_nxt;
};

void norder(void * start, int size);
void horder(void * start, int size);
void nonce(char *ptr, int size);
int ipv6_create_sock();
int ipv4_create_sock();
void print_bit(unsigned int *data);
void print_ipv6_addr(void *ptr);
void print_ipv4_addr(void *ptr);
void ipv6_ntoa(char *result, void *ptr);
int return_ip_version(void *buf);
unsigned short ipv4_checksum(unsigned short *buf, int size);
unsigned short icmp6_checksum(struct ip6_hdr *ip6, unsigned short *payload, int payloadsize);


