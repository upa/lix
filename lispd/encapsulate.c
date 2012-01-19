#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <stdlib.h>
#include <string.h>

#include <linux/types.h>
#include <time.h>

#include "main.h"
#include "utils.h"
#include "encapsulate.h"

void *ipv6_encap_map_request(unsigned int *packetsize, void *buf, int size, void *saddr, void *daddr){
	struct lisp_header6 *h;
	char  *packet = (char *)malloc(size + sizeof(struct lisp_header6));
	memset(packet, 0, size + sizeof(struct lisp_header6));
	
	memcpy(packet + sizeof(struct lisp_header6), buf, size);
	
	h = (struct lisp_header6 *)packet;

	h->TYPE = 8;
	h->RESERVED = 0;
	
	h->VERSION = 6;
	h->TRAFFIC_CLASS = 0xE0;
	h->FLOW_LABEL = 0;
	h->PAYLOAD_LEN = size + 8;
	h->HOP_LIMIT = 64;
	h->NEXT_HEADER = 0x11;

	h->SOURCE_PORT = port_num;
	h->DEST_PORT = 4342;
	h->UDP_LENGTH = size + 8;
	h->UDP_CHECKSUM = 0;

	norder(packet, sizeof(struct lisp_header6));
	memcpy(h->S_EID, saddr, 16);
	memcpy(h->D_EID, daddr, 16);
	*packetsize = size + sizeof(struct lisp_header6);
	return packet;
}

void *ipv4_encap_map_request(unsigned int *packetsize, void *buf, int size, void *saddr, void *daddr){
        struct lisp_header4 *h;
	static int identification;
	unsigned short checksum;
        char  *packet = (char *)malloc(size + sizeof(struct lisp_header4));
        memset(packet, 0, size + sizeof(struct lisp_header4));

        memcpy(packet + sizeof(struct lisp_header4), buf, size);

        h = (struct lisp_header4 *)packet;

        h->TYPE = 8;
        h->RESERVED = 0;

        h->VERSION = 4;
        h->IHL = 5;
        h->TYPE_OF_SERVICE = 0;
        h->TOTAL_LEN = size + sizeof(struct lisp_header4) - 4;

        identification++;      
        h->IDENTIFICATION = identification;
        h->IPFLAGS = 0;
        h->FRAGMENT_OFFSET = 0;

        h->TTL = 64;
        h->PROTOCOL = 0x11;
	h->CHECKSUM = 0;

        h->SOURCE_PORT = port_num;
        h->DEST_PORT = 4342;
        h->UDP_LENGTH = size + 8;
        h->UDP_CHECKSUM = 0;

        norder(packet, sizeof(struct lisp_header4));
        memcpy(h->S_EID, saddr, 4);
        memcpy(h->D_EID, daddr, 4);

        /* calculate ipv4 checksum */
        checksum = ipv4_checksum((unsigned short *)(packet + 4), 20);
        horder(packet, sizeof(struct lisp_header4));
        h->CHECKSUM = htons(checksum);
        norder(packet, sizeof(struct lisp_header4));

        *packetsize = size + sizeof(struct lisp_header4);
        return packet;
}

