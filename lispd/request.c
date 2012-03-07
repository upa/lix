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
#include "encapsulate.h"
#include "request.h"
#include "reply.h"
#include "main.h"
#include "route.h"
#include "parser.h"

int create_map_request_header(int *offset, char *buffer, struct record *request_dest, struct record *rloc_record){
	/* count dest records */
	int dest_record_count = 0;
	struct record *ptr = request_dest;
	while(ptr->next != NULL){
		dest_record_count++;
		ptr = ptr->next;
	}

	/* count rlocs */
	int rloc_record_count = 0;
	ptr = rloc_record;
	while(ptr->next != NULL){
		rloc_record_count++;
		ptr = ptr->next;
	}

	struct map_request_header *header = (struct map_request_header *)buffer;

	header->type = 1;
	header->auth_bit = 0;
	header->map_data_present_bit = 0;
	header->probe_bit = 0;
	header->smr_bit = 0;
	header->pitr_bit = 0;
	header->invoked_bit = 0;
	header->irc = rloc_record_count - 1;
	header->record_count = dest_record_count;
	nonce((char *)&header->nonce, 8);

	*offset += sizeof(struct map_request_header);

	return 0;
}

int create_map_request_source_eid(int *offset, char *buffer, struct record *request_source){
	struct record *ptr = request_source->next;

	if(ptr->af == AF_INET){
		struct map_request_source_eid *source_eid = (struct map_request_source_eid *)(buffer + *offset);
		source_eid->source_eid_afi = IANA_AFI_IPV4;
		*offset += sizeof(struct map_request_source_eid);

		memcpy(buffer + *offset, &(ptr->address), sizeof(struct in_addr));
		*offset += sizeof(struct in_addr);
	}else if(ptr->af == AF_INET6){
		struct map_request_source_eid *source_eid = (struct map_request_source_eid *)(buffer + *offset);
		source_eid->source_eid_afi = IANA_AFI_IPV6;
		*offset += sizeof(struct map_request_source_eid);

		memcpy(buffer + *offset, &(ptr->address), sizeof(struct in6_addr));
		*offset += sizeof(struct in6_addr);
	}

	return 0;
}

int create_map_request_rloc(int *offset, char *buffer, struct record *rloc_record){
	struct record *ptr = rloc_record;

	while(ptr->next != NULL){
		ptr = ptr->next;
		if(ptr->af == AF_INET){
			if(*offset + sizeof(struct map_request_itr_rloc) + sizeof(struct in_addr) > MTU){
				return -1;
			}

			struct map_request_itr_rloc *itr_rloc = (struct map_request_itr_rloc *)(buffer + *offset);
			itr_rloc->itr_rloc_afi = IANA_AFI_IPV4;
			*offset += sizeof(struct map_request_itr_rloc);

			memcpy(buffer + *offset, &(ptr->address), sizeof(struct in_addr));
			*offset += sizeof(struct in_addr);
		}else if(ptr->af == AF_INET6){
			if(*offset + sizeof(struct map_request_itr_rloc) + sizeof(struct in6_addr) > MTU){
				return -1;
			}

			struct map_request_itr_rloc *itr_rloc = (struct map_request_itr_rloc *)(buffer + *offset);
			itr_rloc->itr_rloc_afi = IANA_AFI_IPV6;
			*offset += sizeof(struct map_request_itr_rloc);

			memcpy(buffer + *offset, &(ptr->address), sizeof(struct in6_addr));
			*offset += sizeof(struct in6_addr);
		}
	}

	return 0;
}

int create_map_request_eid(int *offset, char *buffer, struct record *request_dest){
	struct record *ptr = request_dest;

	while(ptr->next != NULL){
		ptr = ptr->next;
		if(ptr->af == AF_INET){
			if(*offset + sizeof(struct map_request_record) + sizeof(struct in_addr) > MTU){
				return -1;
			}

			struct map_request_record *record = (struct map_request_record *)(buffer + *offset);
			record->eid_mask_len = ptr->prefix;
			record->eid_prefix_afi = IANA_AFI_IPV4;
			*offset += sizeof(struct map_request_record);

			memcpy(buffer + *offset, &(ptr->address), sizeof(struct in_addr));
			*offset += sizeof(struct in_addr);
		}else if(ptr->af == AF_INET6){
			if(*offset + sizeof(struct map_request_record) + sizeof(struct in6_addr) > MTU){
				return -1;
			}

			struct map_request_record *record = (struct map_request_record *)(buffer + *offset);
			record->eid_mask_len = ptr->prefix;
			record->eid_prefix_afi = IANA_AFI_IPV6;
			*offset += sizeof(struct map_request_record);

			memcpy(buffer + *offset, &(ptr->address), sizeof(struct in6_addr));
			*offset += sizeof(struct in6_addr);
		}
	}

	return 0;
}

int regist_temporary_cache_by_request(char *buf, struct record *request_dest){
	struct map_request_header *header = (struct map_request_header *)buf;
	struct record *ptr = request_dest;

        while(ptr->next != NULL){
                ptr = ptr->next;
		/* regist temporary route info */
		struct info *newroute = malloc(sizeof(struct info));
		memset(newroute, 0, sizeof(struct info));

		memcpy(newroute->address, &ptr->address, 16);
		memcpy(newroute->nonce, header->nonce, 8);

		newroute->state = STATE_NONCE;
		newroute->prefix = ptr->prefix;
		newroute->ttl = default_ttl * 60;
		newroute->af = 0;
		if(ptr->af == AF_INET){
			ipv4_add_list(newroute);
		}else if(ptr->af == AF_INET6){
			ipv6_add_list(newroute);
		}
	}
}

int create_map_request(char *buffer, struct record *request_source, struct record *request_dest){
	int offset = 0;
	int record_count = 0;
	int ipv6_no_rloc = 0;
	int ipv4_no_rloc = 0;

	struct record rloc_record;	
	memset(&rloc_record, 0, sizeof(struct record));

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

                        add_record(&rloc_record, AF_INET6, 128, address, NULL);
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

                        add_record(&rloc_record, AF_INET, 32, address, NULL);
                }while(addr_list->next != NULL);
        }else{  
                ipv4_no_rloc = 1;
        }

        if(ipv4_no_rloc == 1 && ipv6_no_rloc == 1){
                warn("no rloc configured");
                return;
        }

	if(create_map_request_header(&offset, buffer, request_dest, &rloc_record) < 0){
		return -1;
	}

	/* TODO: request_source is client's address in draft. 
	 * now this is altered by rloc address. implement this! */
	//if(create_map_request_source_eid(&offset, buffer, request_source) < 0){
	if(create_map_request_source_eid(&offset, buffer, &rloc_record) < 0){
		return -1;
	}

	if(create_map_request_rloc(&offset, buffer, &rloc_record) < 0){
		return -1;
	}

	if(create_map_request_eid(&offset, buffer, request_dest) < 0){
		return -1;
	}

	regist_temporary_cache_by_request(buffer, request_dest);
	free_record(&rloc_record);

	return offset;
}

int send_map_request(struct record *request_source, struct record *request_dest){
	int send_size;
	char buffer[MTU];
	int ret = 0;
	char *packet;
	int packet_size;

	memset(buffer, 0, sizeof(buffer));

	ret = create_map_request(buffer, request_source, request_dest);
	if(ret < 0){
		return -1;
	}

	struct sockaddr_storage dest;
	memset(&dest, 0, sizeof(struct sockaddr_storage));
	int sockaddr_size;

	if(control_version == 6){
		struct sockaddr_in6 *dest6 = (struct sockaddr_in6 *)&dest;

                struct config *mapresolver_config = (struct config *)config_root.under_layers[MAPRESOLVER_LAYER];
                if(mapresolver_config == NULL){
                        warn("no ipv6 map-resolver configured");
			return -1;
                }
                struct mapresolver_layer_data *mapresolver_data = (struct mapresolver_layer_data *)(mapresolver_config->data);
                struct address_list *addr_list = &(mapresolver_data->v6address);
                addr_list = addr_list->next;
                if(addr_list == NULL){
                        warn("no ipv6 map-resolver configured");
			return -1;
                }

		dest6->sin6_family = AF_INET6;
		dest6->sin6_port = htons(4342);
		inet_pton(AF_INET6, addr_list->address, &(dest6->sin6_addr));
		sockaddr_size = sizeof(struct sockaddr_in6);
	}else if(control_version == 4){
                struct sockaddr_in *dest4 = (struct sockaddr_in *)&dest;

                struct config *mapresolver_config = (struct config *)config_root.under_layers[MAPRESOLVER_LAYER];
                if(mapresolver_config == NULL){
                        warn("no ipv4 map-resolver configured");
                        return -1;
                }
                struct mapresolver_layer_data *mapresolver_data = (struct mapresolver_layer_data *)(mapresolver_config->data);
                struct address_list *addr_list = &(mapresolver_data->v6address);
                addr_list = addr_list->next;
                if(addr_list == NULL){
                        warn("no ipv4 map-resolver configured");
                        return -1;
                }

                dest4->sin_family = AF_INET;
                dest4->sin_port = htons(4342);
                inet_pton(AF_INET, addr_list->address, &(dest4->sin_addr));
		sockaddr_size = sizeof(struct sockaddr_in);
	}

	packet =  encapsulate_map_request(buffer, ret, &packet_size);
	send_size = sendto(udp_sock, packet, packet_size, 0, (struct sockaddr *)&dest, sockaddr_size);
	if(send_size == -1){
		err(EXIT_FAILURE, "send");
	}

	syslog_write(LOG_INFO, "map-request: message %d byte sent", send_size);

	free(packet);

	return 0;
}

void *ipv6_check_request_queue(void *arg){
	char destination[16];

	/* initiate IPv6 map-request thread */
	if(pthread_mutex_lock(&mutex_reqv6) != 0){
		err(EXIT_FAILURE, "pthread: map-request: lock failed");
	}

	while(1){
		if(check_queue(&ipv6_queue_start) == 1){

			/* lock IPv6 queue mutex */
			if(pthread_mutex_lock(&mutex_queuev6) != 0){
				err(EXIT_FAILURE, "pthread: queuev6: lock failed");
			}

			dequeue(&ipv6_queue_start, destination);

			/* unlock IPv6 queue mutex */
                        if(pthread_mutex_unlock(&mutex_queuev6) != 0){
				err(EXIT_FAILURE, "pthread: queuev6: unlock failed");
                        }

                        struct record request_dest;
                        memset(&request_dest, 0, sizeof(struct record));

                        add_record(&request_dest, AF_INET6, 128, destination, NULL);

                        send_map_request(NULL, &request_dest);
		}else{
			/* wait to next map-request */
			if(pthread_cond_wait(&cond_reqv6, &mutex_reqv6) != 0){
				err(EXIT_FAILURE, "pthread: map-request: wait failed");
			}
		}
	}
}

void *ipv4_check_request_queue(void *arg){
	char destination[16];

	/* initiate IPv4 map-request thread */
	if(pthread_mutex_lock(&mutex_reqv4) != 0){
		err(EXIT_FAILURE, "pthread: map-request: lock failed");
	}

	while(1){
		if(check_queue(&ipv4_queue_start) == 1){

			/* lock IPv4 queue mutex */
			if(pthread_mutex_lock(&mutex_queuev4) != 0){
				err(EXIT_FAILURE, "pthread: queuev4: lock failed");
			}

			dequeue(&ipv4_queue_start, destination);

			/* unlock IPv4 queue mutex */
                        if(pthread_mutex_unlock(&mutex_queuev4) != 0){
				err(EXIT_FAILURE, "pthread: queuev4: unlock failed");
                        }

			struct record request_dest;
			memset(&request_dest, 0, sizeof(struct record));
	
			add_record(&request_dest, AF_INET, 32, destination, NULL);

			send_map_request(NULL, &request_dest);
		}else{
			/* wait to next map-request */
			if(pthread_cond_wait(&cond_reqv4, &mutex_reqv4) != 0){
				err(EXIT_FAILURE, "pthread: map-request: wait failed");
			}
		}
	}
}

