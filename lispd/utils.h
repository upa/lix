#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#define IANA_AFI_IPV4	0x0100
#define IANA_AFI_IPV6	0x0200

union unspec_addr {
	struct in6_addr		v6addr;
	struct in_addr		v4addr;
};

struct record {
	int			af;
	int			prefix;
	union unspec_addr	address;	
	struct			record *next;
	void			*attr;
};

struct pseudo_ipv6_header{
        char		src_address[16],
			dst_address[16];
        u_int32_t	upper_layer_size;
        u_int8_t	ip6_p_pad[3];
        u_int8_t	ip6_p_nxt;
};

int free_record(struct record *start);
int add_record(struct record *record_start, int af, int prefix, char *address, void *attr);
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
void clear_hostbit(int af, char *addr, int prefix);
int clear_bit(void *addr, int prefix);
void syslog_write(int level, char *fmt, ...);
void syslog_open();
void syslog_close();
int get_addr_af(char *addr);


