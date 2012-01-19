#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netdb.h>

#include <stdlib.h>
#include <string.h>

#include <linux/types.h>
#include <time.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include "utils.h"
#include "main.h"

/* convert host byte order buffer to network byte order */
void norder(void * start, int size){
	int s;
	int i = size / 4;
	int *list = start;

	if(size % 4 != 0){
		printf("illegal size of data\n");
	}
	
	for(s = 0; s < i; s++){
		list[s] = htonl(list[s]);	
	}
}

/* convert network byte order buffer to host byte order */
void horder(void * start, int size){
        int s;
        int i = size / 4;
        int *list = start;

        if(size % 4 != 0){
                printf("illegal size of data\n");
        }

        for(s = 0; s < i; s++){
                list[s] = ntohl(list[s]);
        }
}

/* create random nonce */
void nonce(char *ptr, int size){
	int i;
	srand((unsigned)time(NULL));

	for(i = 0; i < size; i++){
		*(ptr + i) = rand() & 0xFF;
	}
}

/* create IPv6 udp socket */
int ipv6_create_sock(){
	int sockfd;
 
	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sockfd < 0)
		return -1;
	return sockfd;
}

/* create IPv4 udp socket */
int ipv4_create_sock(){
        int sockfd;

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
                return -1;
        return sockfd;
}

void print_ipv6_addr(void *ptr){
	struct in6_addr result;
	char r[100];

	memcpy(result.s6_addr, ptr, 16);
	inet_ntop(AF_INET6, &result, r, 100);
	printf("%s", r);
}

void print_ipv4_addr(void *ptr){
        struct in_addr result;
        char r[100];

        memcpy((char *)&(result.s_addr), ptr, 4);
        inet_ntop(AF_INET, &result, r, 100);
        printf("%s", r);
}

void ipv6_ntoa(char *r, void *ptr){
        struct in6_addr result;

        memcpy(result.s6_addr, ptr, 16);
        inet_ntop(AF_INET6, &result, r, 100);
}

int return_ip_version(void *buf){
	struct iphdr *h;
	
	h = (struct iphdr *)buf;
	
	return h->version;
}

unsigned short ipv4_checksum(unsigned short *buf, int size){
	unsigned long sum = 0;

	while (size > 1) {
		sum += *buf++;
		size -= 2;
	}
	if (size)
		sum += *(u_int8_t *)buf;

	sum  = (sum & 0xffff) + (sum >> 16);	/* add overflow counts */
	sum  = (sum & 0xffff) + (sum >> 16);	/* once again */
	
	return ~sum;
}

unsigned short icmp6_checksum(struct ip6_hdr *ip6, unsigned short *payload, int payloadsize){
        unsigned long sum = 0;

        struct pseudo_ipv6_header p;
        unsigned short *f = (unsigned short *)&p;
        int pseudo_size = sizeof(p);

        memset(&p, 0, sizeof(struct pseudo_ipv6_header));
        memcpy(p.src_address, &(ip6->ip6_src), 16);
        memcpy(p.dst_address, &(ip6->ip6_dst), 16);
        p.upper_layer_size = htonl(payloadsize);
        p.ip6_p_nxt = 58;

        while (pseudo_size > 1) {
                sum += *f;
                f++;
                pseudo_size -= 2;
        }

        while (payloadsize > 1) {
                sum += *payload;
                payload++;
                payloadsize -= 2;
        }

        if (payloadsize == 1) {
                sum += *(unsigned char *)payload;
        }

        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);

        return ~sum;
}
