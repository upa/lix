#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "utils.h"
#include "request.h"
#include "reply.h"
#include "main.h"
#include "parser.h"
#include "route.h"

void *receive_response_packet(void *args){
        char buffer[2000];
        int read_size;
        struct reply_header *reply;

        while(1){
                memset(buffer, 0, sizeof(buffer));
                read_size = read(udp_sock, buffer, sizeof(buffer));
                if(read_size < 0){
			err(EXIT_FAILURE, "read failed");
                }

                reply = (struct reply_header *)buffer;

                if(reply->type == 2){
			receive_reply(buffer, read_size);
                }
	}
}

int parse_reply_header(char *buf, int *offset, int *record_count, struct reply_header_attr *header_attr){
	struct reply_header *header = (struct reply_header *)buf;

	*record_count = header->record_count;
	memcpy(header_attr->nonce, header->nonce, 8);

	*offset += sizeof(struct reply_header);
	return 0;
}

int parse_reply_record_header(char *buf, int *offset, int *locator_count, struct record *eid){
	struct reply_record_header *header = (struct reply_record_header *)buf;
	struct reply_record_attr *attr = (struct reply_record_attr *)malloc(sizeof(struct reply_record_attr));
	int af;
	int prefix;
	char address[16];
	int record_size = 0;

	memset(attr, 0, sizeof(struct reply_record_attr));
	memset(address, 0, 16);

	*locator_count = header->locator_count;
	attr->record_ttl = ntohl(header->record_ttl);
	attr->act = header->act;

	if(header->eid_prefix_afi == IANA_AFI_IPV4){
		af = AF_INET;
		if((prefix = header->eid_mask_len) > 32){
			return -1;
		}
		record_size = sizeof(struct reply_record_header) + 4;
	}else if(header->eid_prefix_afi == IANA_AFI_IPV6){
		af = AF_INET6;
		if((prefix = header->eid_mask_len) > 128){
			return -1;
		}
		record_size = sizeof(struct reply_record_header) + 16;
	}else{
		return -1;
	}

	memcpy(address, buf + sizeof(struct reply_record_header), 16);
	clear_hostbit(af, address, prefix);
	add_record(eid, af, prefix, address, attr);

	*offset += record_size;
	return 0; 
}

int parse_reply_locator_header(char *buf, int *offset, struct record *locators){
	struct reply_locator_header *header = (struct reply_locator_header *)buf;
	struct reply_locator_attr *attr = (struct reply_locator_attr *)malloc(sizeof(struct reply_locator_attr));
	int af;
	char address[16];
	int locator_size;

	memset(attr, 0, sizeof(struct reply_locator_attr));
	memset(address, 0, 16);

	attr->priority = header->priority;
	attr->weight = header->weight;

	if(header->locator_afi == IANA_AFI_IPV4){
		af = AF_INET;
		locator_size = sizeof(struct reply_locator_header) + 4;
	}else if(header->locator_afi == IANA_AFI_IPV6){
		af = AF_INET6;
		locator_size = sizeof(struct reply_locator_header) + 16;
	}else{
		return -1;
	}

	memcpy(address, buf + sizeof(struct reply_locator_header), 16);
	add_record(locators, af, 0, address, attr);

	*offset += locator_size;
	return 0;
}

int add_reply_cache(struct reply_header_attr *attr, struct record *eid, struct record *locators){
	struct record *eid_record = eid->next;
	struct record *rloc_record = locators->next;
	struct reply_record_attr *eid_attr;
	struct reply_locator_attr *rloc_attr;
	char *network;
	int eid_prefix;
	int eid_af;
	char *nexthop;
	int rloc_af;

	if(eid_record == NULL){
		return -1;
	}

	eid_attr = eid_record->attr;
	network = (char *)&(eid_record->address);
	eid_prefix = eid_record->prefix;
	if(eid_record->af == AF_INET){
		eid_af = 1;
	}else if(eid_record->af == AF_INET6){
		eid_af = 2;
	}

	if(rloc_record == NULL){
		/* negative cache regist */
		int ret;
		if(eid_record->af == AF_INET){
                	ret = ipv4_rem_list_by_nonce((char *)attr->nonce);
		}else if(eid_record->af == AF_INET6){
			ret = ipv6_rem_list_by_nonce((char *)attr->nonce);
		}

		if(ret < 0){
			return -1;	
		}

		regist_prefix(eid_af, (char *)&eid_record->address, eid_record->prefix, NULL, 0);

                /* regist route info */
		struct info *newroute = malloc(sizeof(struct info));
		memset(newroute, 0, sizeof(struct info));
		memcpy(newroute->address, &eid_record->address, 16);
		newroute->state = STATE_TTL;
		newroute->prefix = eid_record->prefix;
		newroute->af = 0;
		if(eid_attr->record_ttl == 0xffffffff){
			newroute->ttl = default_ttl * 60;
		}else{
                       	newroute->ttl = eid_attr->record_ttl * 60;
		}

		if(eid_record->af == AF_INET){
			ipv4_add_list(newroute);
		}else if(eid_record->af == AF_INET6){
			ipv6_add_list(newroute);
		}
	}else{
		rloc_attr = rloc_record->attr;
		if(rloc_record->af == AF_INET){
			rloc_af = 1;	
		}else if(rloc_record->af == AF_INET6){
			rloc_af = 2;
		}

                int ret;
                if(eid_record->af == AF_INET){
                        ret = ipv4_rem_list_by_nonce((char *)attr->nonce);
                }else if(eid_record->af == AF_INET6){
                        ret = ipv6_rem_list_by_nonce((char *)attr->nonce);
                }

                if(ret < 0){
                        return -1;     
                }

                regist_prefix(eid_af, (char *)&eid_record->address, eid_record->prefix, (char *)&rloc_record->address, rloc_af);

                /* regist route info */
                struct info *newroute = malloc(sizeof(struct info));
                memset(newroute, 0, sizeof(struct info)); 
                memcpy(newroute->address, (char *)&eid_record->address, 16);
		memcpy(newroute->nexthop, (char *)&rloc_record->address, 16);
                newroute->state = STATE_TTL;
                newroute->prefix = eid_record->prefix;
                newroute->af = rloc_af;
                if(eid_attr->record_ttl == 0xffffffff){
                        newroute->ttl = default_ttl * 60;
                }else{  
                        newroute->ttl = eid_attr->record_ttl * 60;
                }       

                if(eid_record->af == AF_INET){
                        ipv4_add_list(newroute);
                }else if(eid_record->af == AF_INET6){
                        ipv6_add_list(newroute);
                }
	}

	return 0;
}

int receive_reply(char *buf, int size){
	int offset = 0;
	int record_count = 0;
	struct reply_header_attr header_attr;

	parse_reply_header(buf, &offset, &record_count, &header_attr);

	int i;
	for(i = 0; i < record_count; i++){
		struct record	eid;
		struct record	locators;
		int locator_count = 0;

		memset(&eid, 0, sizeof(struct record));
		memset(&locators, 0, sizeof(struct record));

		if(parse_reply_record_header(buf + offset, &offset, &locator_count, &eid) < 0){
			return -1;
		}

		int s;
		for(s = 0; s < locator_count; s++){
			if(parse_reply_locator_header(buf + offset, &offset, &locators) < 0){
				free_record(&eid);
				free_record(&locators);
				return -1;
			}
		}

		add_reply_cache(&header_attr, &eid, &locators);
		free_record(&eid);
		free_record(&locators);
	}

	return 0;
}







