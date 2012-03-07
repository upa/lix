#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netdb.h>
#include <syslog.h>

#include <stdlib.h>
#include <string.h>

#include <linux/types.h>
#include <time.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <stdarg.h>

#include "utils.h"
#include "main.h"

int free_record(struct record *start){
	struct record *ptr = start;
	struct record *prev;

	ptr = ptr->next;
	if(ptr == NULL){
		return -1;
	}

	do{
		prev = ptr;
		ptr = ptr->next;

		if(prev->attr != NULL){
			free(prev->attr);
		}
		free(prev);
	}while(ptr != NULL);

	return 0;
}

int add_record(struct record *record_start, int af, int prefix, char *address, void *attr){
	struct record *ptr = record_start;

	while(ptr->next != NULL){
		ptr = ptr->next;
	}

	ptr->next = (struct record *)malloc(sizeof(struct record));
	memset(ptr->next, 0, sizeof(struct record));

	ptr = ptr->next;
	ptr->af = af;
	ptr->prefix = prefix;
	ptr->attr = attr;

	if(af == AF_INET){
		memcpy(&ptr->address, address, sizeof(struct in_addr));
	}else if(af == AF_INET6){
		memcpy(&ptr->address, address, sizeof(struct in6_addr));
	}

	return 0;
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

void clear_hostbit(int af, char *addr, int prefix){
	int target;
	int i;

	if(af == AF_INET){
		target = 32;

	}else if(af == AF_INET6){
		target = 128;
	}

	for(i = prefix + 1; i <= target; i++){
		clear_bit(addr, i);
	}

}

int clear_bit(void *addr, int prefix){
	int i = (prefix - 1) / 32;
	int j = prefix - (i * 32);

	unsigned int temp = 1 << (32 - j);
	unsigned int *ptr = addr;
	unsigned int s = htonl(ptr[i]);

	ptr[i] = ntohl(s & ~temp);
}

void syslog_write(int level, char *fmt, ...){
	va_list args;
	va_start(args, fmt);
	char buffer[1024];

	vsprintf(buffer, fmt, args);

	syslog_open();
	syslog(level, buffer);
	syslog_close();

	va_end(args);
}

void syslog_open(){
    openlog(PROCESS_NAME, LOG_CONS | LOG_PID, syslog_facility);
}

void syslog_close() {
    closelog();
}

int get_addr_af(char *addr){
        struct addrinfo hints, * res;
        memset (&hints, 0, sizeof (hints));
        hints.ai_family = AF_UNSPEC;
	int af;
        
        if (getaddrinfo (addr, NULL, &hints, &res) != 0) {
		err(EXIT_FAILURE, "error while getting af of address");
        }

	af = res->ai_family;
        
        freeaddrinfo (res);

	return af;
}


