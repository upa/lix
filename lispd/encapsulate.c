#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <syslog.h>
#include <time.h>

#include "utils.h"
#include "request.h"
#include "encapsulate.h"
#include "main.h"
#include "parser.h"


int create_lisp_header(char *buf){
	struct lisp_hdr *lisp = (struct lisp_hdr *)buf;

	lisp->type = 8;

	return sizeof(struct lisp_hdr);
}

int create_ipv6_header(char *buf, int plen){
        char rloc[16];
	char resolver[16];

        struct config *rloc_config = (struct config *)config_root.under_layers[RLOC_LAYER];
        if(rloc_config == NULL){
                warn("no rloc configured");
                return -1;
        }
        struct rloc_layer_data *rloc_data = (struct rloc_layer_data *)(rloc_config->data);
        struct address_list *addr_list = &(rloc_data->v6address);
	addr_list = addr_list->next;
        if(addr_list == NULL){
                warn("no rloc configured");
		return -1;
        }

	inet_pton(AF_INET6, addr_list->address, rloc);

	struct config *mapresolver_config = (struct config *)config_root.under_layers[MAPRESOLVER_LAYER];
	if(mapresolver_config == NULL){
		warn("no resolver configured");
		return -1;
	}
	struct mapresolver_layer_data *mapresolver_data = (struct mapresolver_layer_data *)(mapresolver_config->data);
	addr_list = &(mapresolver_data->v6address);
	addr_list = addr_list->next;
	if(addr_list == NULL){
		err("no resolver configured");
		return -1;
	}

	inet_pton(AF_INET6, addr_list->address, resolver);


	struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;

	ip6->ip6_vfc = 6 << 4;
	ip6->ip6_plen = htons(plen);
	ip6->ip6_nxt = IPPROTO_UDP;
	ip6->ip6_hlim = 0x40;

	memcpy(&(ip6->ip6_src), rloc, 16);
	memcpy(&(ip6->ip6_dst), resolver, 16);

	return sizeof(struct ip6_hdr);
}

int create_ipv4_header(char *buf, int plen){
        char rloc[16];
        char resolver[16];

        struct config *rloc_config = (struct config *)config_root.under_layers[RLOC_LAYER];
        if(rloc_config == NULL){
                warn("no rloc configured");
                return -1;
        }
        struct rloc_layer_data *rloc_data = (struct rloc_layer_data *)(rloc_config->data);
        struct address_list *addr_list = &(rloc_data->v4address);
        addr_list = addr_list->next;
        if(addr_list == NULL){
                warn("no rloc configured");
                return -1;
        }

        inet_pton(AF_INET, addr_list->address, rloc);

        struct config *mapresolver_config = (struct config *)config_root.under_layers[MAPRESOLVER_LAYER];
        if(mapresolver_config == NULL){
                warn("no resolver configured");
                return -1;
        }
        struct mapresolver_layer_data *mapresolver_data = (struct mapresolver_layer_data *)(mapresolver_config->data);
        addr_list = &(mapresolver_data->v4address);
        addr_list = addr_list->next;
        if(addr_list == NULL){
                err("no resolver configured");
                return -1;
        }

        inet_pton(AF_INET, addr_list->address, resolver);

	static int identification;
	struct iphdr *ip = (struct iphdr *)buf;
	unsigned short checksum;

	identification++;

	ip->ihl = 5;
	ip->version = 4;
	ip->tot_len = htons(plen);
	ip->id = htons(identification);
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	ip->check = 0;

	memcpy(&(ip->saddr), rloc, 4);
	memcpy(&(ip->daddr), resolver, 4);

	ip->check = ipv4_checksum((unsigned short *)buf, ip->ihl * 4);

	return sizeof(struct iphdr);
}

int create_udp_header(char *buf, int plen){
	struct udphdr *udp = (struct udphdr *)buf;

	udp->source = htons(port_num);
	udp->dest = htons(4342);
	udp->len = htons(plen);
	udp->check = 0;

	return sizeof(struct udphdr);
}

char *encapsulate_map_request(char *buf, int size, int *encapsulated_size){
	char *encapsulated_packet;
	int offset = 0;
	int plen = 0;
	if(control_version == 6){
		plen = sizeof(struct lisp_hdr) + sizeof(struct ip6_hdr) + sizeof(struct udphdr) + size;
		if(plen > MTU){
			return NULL;
		}
		encapsulated_packet = (char *)malloc(plen);
		memset(encapsulated_packet, 0, plen);
		offset += create_ipv6_header(encapsulated_packet + sizeof(struct lisp_hdr), plen - (sizeof(struct ip6_hdr) + sizeof(struct lisp_hdr)));
	}else if(control_version == 4){
		plen = sizeof(struct lisp_hdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + size;
		if(plen > MTU){
			return NULL;
		}
		encapsulated_packet = (char *)malloc(plen);
		memset(encapsulated_packet, 0, plen);
		offset += create_ipv4_header(encapsulated_packet + sizeof(struct lisp_hdr), plen - sizeof(struct lisp_hdr));
	}

	offset += create_lisp_header(encapsulated_packet);
	offset += create_udp_header(encapsulated_packet + offset, plen - offset);
	
	memcpy(encapsulated_packet + offset, buf, size);
	offset += size;

	*encapsulated_size = offset;
	return encapsulated_packet;
}

