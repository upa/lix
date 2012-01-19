#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <stdlib.h>
#include <string.h>

#include <linux/types.h>
#include <openssl/hmac.h>
#include <pthread.h>
#include <time.h>

#include "main.h"
#include "utils.h"
#include "register.h"

/* calc HMAC-SHA-1 */
void hmac(char *md, void *buf, size_t size){
        char key[] = AUTH_KEY;
        size_t keylen = strlen(key);
        size_t reslen;
	char result[SHA_DIGEST_LENGTH];
	
	HMAC(EVP_sha1(), key, keylen, buf, size, result, (unsigned int *)&reslen);
	memcpy(md, result, SHA_DIGEST_LENGTH);
}

void ipv4_create_register_data(struct reg_data4 *data, int rflag, char *eid, int prefix){
        struct in_addr eid_prefix;
        struct in_addr my_address;

        inet_pton(AF_INET, eid, &eid_prefix);
        inet_pton(AF_INET, RLOC4, &my_address);

	memset(data, 0, sizeof(struct reg_data4));

        /* Information of Rloc-EID mapping */
        data->TTL = 60;
        data->LOC_COUNT = 1;
        data->EID_MASKLEN = prefix;

        /* Unused flags */
        data->ACT = 0;
        data->A = 1;
        data->MAP_VERSION_NUM = 0;

        /* AF of EID */
        data->EID_AFI = 1;

        /* Priority and weight */
        data->PRIORITY = 0;
        data->WEIGHT = 100;

        /* Multicast priority (Unused) */
        data->M_PRIORITY = 255;
        data->M_WEIGHT = 0;

        /* Unused flags */
        data->L = 1;
        data->P = 0;
        data->R = rflag;
        data->UNUSED_FLAGS = 0;

        /* AF of Rloc */
        data->LOC_AFI = 1;

        norder(data, sizeof(struct reg_data4));

        memcpy(data->EID_PREFIX, (char *)&(eid_prefix.s_addr), 4);
        memcpy(data->LOCATER, (char *)&(my_address.s_addr), 4);
}


void ipv6_create_register_data(struct reg_data6 *data, int rflag, char *eid, int prefix){
        struct in6_addr eid_prefix;
        struct in6_addr my_address;

        inet_pton(AF_INET6, eid, &eid_prefix);
        inet_pton(AF_INET6, RLOC6, &my_address);

	memset(data, 0, sizeof(struct reg_data6));

        /* Information of Rloc-EID mapping */
        data->TTL = 60;
        data->LOC_COUNT = 1;
        data->EID_MASKLEN = prefix;

        /* Unused flags */
        data->ACT = 0;
        data->A = 1;
        data->MAP_VERSION_NUM = 0;

        /* AF of EID */
        data->EID_AFI = 2;

        /* Priority and weight */
        data->PRIORITY = 0;
        data->WEIGHT = 100;

        /* Multicast priority (Unused) */
        data->M_PRIORITY = 255;
        data->M_WEIGHT = 0;

        /* Unused flags */
        data->L = 1;
        data->P = 0;
        data->R = rflag;
        data->UNUSED_FLAGS = 0;

        /* AF of Rloc */
        data->LOC_AFI = 2;

        norder(data, sizeof(struct reg_data6));

        memcpy(data->EID_PREFIX, eid_prefix.s6_addr, 16);
        memcpy(data->LOCATER, my_address.s6_addr, 16);
}

/* create Map-Register packet */
char *create_register_packet(int *packet_size, struct prefixes *start, int rflag){
	int reqsize = 0;
	struct reg_header *h;
	int record_count = 0;
	struct prefixes *ptr = start;
	char *req;

	req = malloc(sizeof(struct reg_header));
	h = (struct reg_header *)req;
	reqsize += sizeof(struct reg_header);

	/* Basic packet information */
	h->TYPE = 3;
	h->P = 1;
	h->RESERVED = 0;

	/* create nonce */
	nonce(h->NONCE, 8);

	/* Authentication */
	h->KEY_ID = 1;
	h->AUTH_DATA_LENGTH = SHA_DIGEST_LENGTH;
	memset(h->AUTH_DATA, 0, SHA_DIGEST_LENGTH);

	while(ptr->next != NULL){
		record_count++;
		ptr = ptr->next;
		if(ptr->version == 6){
			int offset = reqsize;
			reqsize += sizeof(struct reg_data6);
			req = realloc(req, reqsize);
			h =(struct reg_header *) req;
			ipv6_create_register_data((struct reg_data6 *)(req + offset), rflag, ptr->eid, ptr->prefix);
                }else if(ptr->version == 4){
                        int offset = reqsize;
                        reqsize += sizeof(struct reg_data4);
                        req = realloc(req, reqsize);
                        h = (struct reg_header *)req;
                        ipv4_create_register_data((struct reg_data4 *)(req + offset), rflag, ptr->eid, ptr->prefix);
                }
	}

	h->REC_COUNT = record_count;

	norder(h, sizeof(struct reg_header));
	hmac(h->AUTH_DATA, req, reqsize);

	*packet_size = reqsize;
	return req;
}


void *send_map_register(void *arg){
	void *req;
	struct prefixes start;
	struct prefixes *ptr;
	int fd;
	int send_size;
	int i;
	int dest_size;
	void *dest;

	memset(&start, 0, sizeof(struct prefixes));

//IMPLEMENT READ CONFIGURATION!!
	start.next = malloc(sizeof(struct prefixes));
	ptr = start.next;
	memset(ptr, 0, sizeof(struct prefixes));
	strcpy(ptr->eid, EID6);
	ptr->prefix = PREFIX6;
	ptr->version = 6;

	ptr->next = malloc(sizeof(struct prefixes));
	ptr = ptr->next;
	memset(ptr, 0, sizeof(struct prefixes));
	strcpy(ptr->eid, EID4);
	ptr->prefix = PREFIX4;
	ptr->version = 4;


	if(CONTROL_VERSION == 6){
		struct sockaddr_in6 dest6;

		memset(&dest6, 0, sizeof(dest6));
		dest6.sin6_family = AF_INET6;
		dest6.sin6_port = htons(4342);
		inet_pton(AF_INET6, MAP_SERVER6, &dest6.sin6_addr);

		dest_size = sizeof(dest6);
		dest = &dest6;
	}else if(CONTROL_VERSION == 4){
		struct sockaddr_in dest4;

		memset(&dest4, 0, sizeof(dest4));
       		dest4.sin_family = AF_INET;
	        dest4.sin_port = htons(4342);
       		inet_pton(AF_INET, MAP_SERVER4, &dest4.sin_addr);

		dest_size = sizeof(dest4);
		dest = &dest4;
	}
	
	/* initiate register thread */
        if(pthread_mutex_lock(&mutex_reg) != 0){
                printf("pthread: register: lock failed\n");
                exit(1);
        }

	printf("Fast Map-regist signaling\n");
	for(i = 0; i < 5; i++){
		int packet_size;
		req = create_register_packet(&packet_size, &start, 0);
		send_size = sendto(udp_sock, req, packet_size, 0, (struct sockaddr *)dest, dest_size);
                if(send_size == -1){
                        perror("send");
                        exit(1);
                }
                sleep(1);
	}

	/* signaling to main thread */
	if(pthread_cond_signal(&cond_reg) != 0){
		printf("pthread: register: cond_signal failed\n");
		exit(1);
	}

        /* finalize initiation */
        if(pthread_mutex_unlock(&mutex_reg) != 0){
                printf("pthread: register: unlock failed\n");
                exit(1);
        }

	printf("sending register message\n");
	while(1){
		int packet_size;
		req = create_register_packet(&packet_size, &start, 1);
		send_size = sendto(udp_sock, req, packet_size, 0, (struct sockaddr *)dest, dest_size);
		if(send_size == -1){
			perror("send");
			exit(1);
		}
		sleep(60);
	}

}

