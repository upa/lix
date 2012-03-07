#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <err.h>

#include <stdlib.h>
#include <string.h>

#include <linux/types.h>
#include <openssl/hmac.h>
#include <pthread.h>
#include <time.h>

#include "utils.h"
#include "request.h"
#include "register.h"
#include "main.h"
#include "parser.h"


/* calc HMAC-SHA-1 */
void hmac(char *md, void *buf, size_t size){
        size_t keylen = strlen(authentication_key);
        size_t reslen;
	char result[SHA_DIGEST_LENGTH];
	
	HMAC(EVP_sha1(), authentication_key, keylen, buf, size, result, (unsigned int *)&reslen);
	memcpy(md, result, SHA_DIGEST_LENGTH);
}

int create_map_register_header(char *buf, int *offset, struct record *request_dest){
	/* count dest records */
	int dest_record_count = 0;
	struct record *ptr = request_dest;
	while(ptr->next != NULL){
		dest_record_count++;
		ptr = ptr->next;
	}

	struct register_header *header = (struct register_header *)buf;

	header->type = 3;
	header->proxy_bit = 1;
	header->notify_bit = 0;
	header->record_count = dest_record_count;
	nonce((char *)header->nonce, 8);
	header->key_id = htons(1);
	header->auth_len = htons(SHA_DIGEST_LENGTH);

	*offset += sizeof(struct register_header);
	return 0;
}

int create_map_register_record(char *buf, int *offset, struct record *request_dest, struct record *request_source){
        /* count locators */
        int locator_count = 0;
        struct record *ptr = request_source;
        while(ptr->next != NULL){
                locator_count++;
                ptr = ptr->next;
        }

	int record_len = 0;
	struct register_record *header = (struct register_record *)buf;
	struct register_record_attr *attr = request_dest->attr;

	header->record_ttl = htonl(attr->record_ttl);
	header->locator_count = locator_count;
	header->eid_mask_len = request_dest->prefix;
	header->act = attr->act;

	if(request_dest->af == AF_INET){
		header->eid_prefix_afi = IANA_AFI_IPV4;
		record_len += sizeof(struct register_record);
		memcpy(buf + record_len, &request_dest->address, 4);
		record_len += 4;
	}else if(request_dest->af == AF_INET6){
		header->eid_prefix_afi = IANA_AFI_IPV6;
		record_len += sizeof(struct register_record);
		memcpy(buf + record_len, &request_dest->address, 16);
		record_len += 16;
	}

	*offset += record_len;
	return 0;
}

int create_map_register_locator(char *buf, int *offset, struct record *request_source){
	int locator_len = 0;
	struct register_locator *header = (struct register_locator *)buf;
	struct register_locator_attr *attr = request_source->attr;

	header->priority = attr->priority;
	header->weight = attr->weight;
	header->route_bit = 1;
	header->local_bit = 1;

	if(request_source->af == AF_INET){
		header->locator_afi = IANA_AFI_IPV4;
		locator_len += sizeof(struct register_locator);
		memcpy(buf + locator_len, &request_source->address, 4);
		locator_len += 4;
	}else if(request_source->af == AF_INET6){
		header->locator_afi = IANA_AFI_IPV6;
		locator_len += sizeof(struct register_locator);
		memcpy(buf + locator_len, &request_source->address, 16);
		locator_len += 16;
	}

	*offset += locator_len;
	return 0;
}

int create_map_register(char *buf, struct record *request_dest, struct record *request_source){
	int offset = 0;
	struct record *eid_record = request_dest->next;
	struct register_record_attr *eid_attr;

	create_map_register_header(buf, &offset, request_dest);
	offset += SHA_DIGEST_LENGTH;

	while(eid_record != NULL){
		create_map_register_record(buf + offset, &offset, eid_record, request_source);
		eid_attr = eid_record->attr;

		struct record *rloc_record = request_source->next;
		while(rloc_record != NULL){
			create_map_register_locator(buf + offset, &offset, rloc_record);
			rloc_record = rloc_record->next;
		}

		eid_record = eid_record->next;
	}

	hmac(buf + sizeof(struct register_header), buf, offset);

	return offset;
}

int send_map_register(struct record *request_dest, struct record *request_source){
	char buffer[MTU];

        struct sockaddr_storage dest;
        memset(&dest, 0, sizeof(struct sockaddr_storage));
        int sockaddr_size;
	int i;
	int send_size;

        if(control_version == 6){
                struct sockaddr_in6 *dest6 = (struct sockaddr_in6 *)&dest;

	        struct config *mapserver_config = (struct config *)config_root.under_layers[MAPSERVER_LAYER];
       		struct mapserver_layer_data *mapserver_data = (struct mapserver_layer_data *)(mapserver_config->data);
        	struct address_list *addr_list = &(mapserver_data->v6address);
        	addr_list = addr_list->next;

                dest6->sin6_family = AF_INET6;
                dest6->sin6_port = htons(4342);
                inet_pton(AF_INET6, addr_list->address, &(dest6->sin6_addr));
                sockaddr_size = sizeof(struct sockaddr_in6);
        }else if(control_version == 4){
                struct sockaddr_in *dest4 = (struct sockaddr_in *)&dest;

                struct config *mapserver_config = (struct config *)config_root.under_layers[MAPSERVER_LAYER];
                struct mapserver_layer_data *mapserver_data = (struct mapserver_layer_data *)(mapserver_config->data);
                struct address_list *addr_list = &(mapserver_data->v4address);
                addr_list = addr_list->next;

                dest4->sin_family = AF_INET;
                dest4->sin_port = htons(4342);
                inet_pton(AF_INET, addr_list->address, &(dest4->sin_addr));
                sockaddr_size = sizeof(struct sockaddr_in);
        }

	/* initiate register thread */
        if(pthread_mutex_lock(&mutex_reg) != 0){
		err(EXIT_FAILURE, "pthread: register: lock failed");
        }

	syslog_write(LOG_INFO, "Initial fast map-regist signaling");

	for(i = 0; i < 5; i++){
		memset(buffer, 0, sizeof(buffer));
		int ret = create_map_register(buffer, request_dest, request_source);
		if(ret < 0){
			return -1;
		}

		send_size = sendto(udp_sock, buffer, ret, 0, (struct sockaddr *)&dest, sockaddr_size);
                if(send_size == -1){
			err(EXIT_FAILURE, "send");
                }
                sleep(1);
	}

	/* signaling to main thread */
	if(pthread_cond_signal(&cond_reg) != 0){
		err(EXIT_FAILURE, "pthread: register: cond_signal failed");
	}

        /* finalize initiation */
        if(pthread_mutex_unlock(&mutex_reg) != 0){
		err(EXIT_FAILURE, "pthread: register: unlock failed");
        }

	syslog_write(LOG_INFO, "Started normal map-regist per %d sec", MAPREGIST_INTERVAL);

	while(1){
		memset(buffer, 0, sizeof(buffer));
		int ret = create_map_register(buffer, request_dest, request_source);
		if(ret < 0){
			return -1;
		}

		send_size = sendto(udp_sock, buffer, ret, 0, (struct sockaddr *)&dest, sockaddr_size);
		if(send_size == -1){
			err(EXIT_FAILURE, "send");
		}
		sleep(MAPREGIST_INTERVAL);
	}

	return 0;
}

void *start_map_register(void *arg){
	int ipv4_no_eid = 0;
	int ipv6_no_eid = 0;
	int ipv4_no_rloc = 0;
	int ipv6_no_rloc = 0;

        struct record request_dest;
        struct record request_source;
        memset(&request_dest, 0, sizeof(struct record));
        memset(&request_source, 0, sizeof(struct record));

	/* read rloc config */
        struct config *rloc_config = (struct config *)config_root.under_layers[RLOC_LAYER];
	if(rloc_config == NULL){
		warn("no rloc configured");
		return;
	}
        struct rloc_layer_data *rloc_data = (struct rloc_layer_data *)(rloc_config->data);

	struct address_list *addr_list = &(rloc_data->v6address);
        if(addr_list->next != NULL){
                do{
                        addr_list = addr_list->next;

		        char address[16];
		        inet_pton(AF_INET6, addr_list->address, address);

		        struct register_locator_attr *attr = malloc(sizeof(struct register_locator_attr));
		        attr->priority = 0;
		        attr->weight = 100;
		        add_record(&request_source, AF_INET6, 128, address, attr);
                }while(addr_list->next != NULL);
        }else{
                ipv6_no_rloc = 1;
        }

        addr_list = &(rloc_data->v4address);
        if(addr_list->next != NULL){
                do{
                        addr_list = addr_list->next;

                        char address[4];
                        inet_pton(AF_INET, addr_list->address, address);

                        struct register_locator_attr *attr = malloc(sizeof(struct register_locator_attr));
                        attr->priority = 0;
                        attr->weight = 100;
                        add_record(&request_source, AF_INET, 32, address, attr);
                }while(addr_list->next != NULL);
        }else{
                ipv4_no_rloc = 1;
        }

        if(ipv4_no_rloc == 1 && ipv6_no_rloc == 1){
                warn("no rloc configured");
		return;
        }

	/* read eid config */
	struct config *eid_config = (struct config *)config_root.under_layers[EID_LAYER];
	if(eid_config == NULL){
		warn("no eid configured");
		return;
	}
	struct eid_layer_data *eid_data = (struct eid_layer_data *)(eid_config->data);

	addr_list = &(eid_data->v6prefix);
	if(addr_list->next != NULL){
		do{
			addr_list = addr_list->next;

                        char address[16];
                        inet_pton(AF_INET6, addr_list->address, address);

		        struct register_record_attr *attr = malloc(sizeof(struct register_record_attr));
		        attr->record_ttl = default_ttl;
		        attr->act = 0;
			add_record(&request_dest, AF_INET6, addr_list->prefix, address, attr);
		}while(addr_list->next != NULL);
	}else{
		ipv6_no_eid = 1;
	}

        addr_list = &(eid_data->v4prefix);
	if(addr_list->next != NULL){
        	do{
        	        addr_list = addr_list->next;

                        char address[4];
                        inet_pton(AF_INET, addr_list->address, address);

                        struct register_record_attr *attr = malloc(sizeof(struct register_record_attr));
                        attr->record_ttl = default_ttl;
                        attr->act = 0;
                        add_record(&request_dest, AF_INET, addr_list->prefix, address, attr);
        	}while(addr_list->next != NULL);
	}else{
		ipv4_no_eid = 1;
	}

	if(ipv4_no_eid == 1 && ipv6_no_eid == 1){
		err(EXIT_FAILURE, "no eid configured");
	}

	send_map_register(&request_dest, &request_source);

	free_record(&request_dest);
	free_record(&request_source);
}
