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
#include "request.h"
#include "encapsulate.h"
#include "queue.h"
#include "route.h"

void ipv4_create_request_packet(struct req_mes4 *req, int reqsize, char * rloc_addr, char * dest_addr, char * source_addr, int query_prefix){
        unsigned int afi = 0;

        req->h.TYPE = 1;
        req->h.A = 0;
        req->h.M = 0;
        req->h.P = 0;
        req->h.S = 0;
        req->h.RESERVED = 0;
        req->h.IRC = 0;
        req->h.REC_COUNT = 1;
        nonce(req->h.NONCE, 8);

        req->d.D_EID_AFI = 1;
        req->d.D_EID_MASKLEN = query_prefix;

        req->d.RESERVED = 0;

        /* regist temporary route info */
        struct info *newroute = malloc(sizeof(struct info));
        memset(newroute, 0, sizeof(struct info));
        memcpy(newroute->address, dest_addr, 16);
        memcpy(newroute->nonce, req->h.NONCE, 8);
        newroute->state = STATE_NONCE;
        newroute->prefix = query_prefix;
	newroute->ttl = 3600;
        ipv4_add_list(newroute);

        norder(req, reqsize);

        afi = 1 << 8;
        /* 00000000 00000001 00000000 00000000
           in LITTLE ENDIAN -> copy front 2octed
        */

        memcpy(req->d.ITR_RLOC, rloc_addr, 4);
        memcpy(req->d.D_EID, dest_addr, 4);

        memcpy(&(req->d.S_EIDAFI_EID_RLOCAFI[2]), source_addr, 4);
        memcpy(&(req->d.S_EIDAFI_EID_RLOCAFI[0]), &afi, 2);
        memcpy(&(req->d.S_EIDAFI_EID_RLOCAFI[6]), &afi, 2);
}

void ipv6_create_request_packet(struct req_mes6 *req, int reqsize, char * rloc_addr, char * dest_addr, char * source_addr, int query_prefix){
	unsigned int afi = 0;
	
	req->h.TYPE = 1;
	req->h.A = 0;
	req->h.M = 0;
	req->h.P = 0;
	req->h.S = 0;
	req->h.RESERVED = 0;
	req->h.IRC = 0;
	req->h.REC_COUNT = 1;
	nonce(req->h.NONCE, 8);

	req->d.D_EID_AFI = 2;
	req->d.D_EID_MASKLEN = query_prefix;

	req->d.RESERVED = 0;

	/* regist temporary route info */
        struct info *newroute = malloc(sizeof(struct info));
        memset(newroute, 0, sizeof(struct info));
        memcpy(newroute->address, dest_addr, 16);
	memcpy(newroute->nonce, req->h.NONCE, 8);
	newroute->state = STATE_NONCE;
        newroute->prefix = query_prefix;
	newroute->ttl = 3600;
	ipv6_add_list(newroute);


	norder(req, reqsize);

	afi = 1 << 9;
	/* 00000000 00000010 00000000 00000000 
	   in LITTLE ENDIAN -> copy front 2octed
	*/
	
	memcpy(req->d.ITR_RLOC, rloc_addr, 16);
	memcpy(req->d.D_EID, dest_addr, 16);

	memcpy(&(req->d.S_EIDAFI_EID_RLOCAFI[2]), source_addr, 16);
	memcpy(&(req->d.S_EIDAFI_EID_RLOCAFI[0]), &afi, 2);
	memcpy(&(req->d.S_EIDAFI_EID_RLOCAFI[18]), &afi, 2);
}

int ipv4_send_map_request(char *lisp_dest_addr, int lisp_prefix){
	char *packet;
	struct req_mes4 req;
	int packetsize;
	int fd;
	int send_size;

        struct in_addr lisp_source4;
        inet_pton(AF_INET, RLOC4, &lisp_source4);

        struct timeval socket_timeout;
        void *dest;
        int dest_size;

	if(CONTROL_VERSION == 6){
		struct sockaddr_in6 dest6;

		memset(&dest6, 0, sizeof(dest6));
		dest6.sin6_family = AF_INET6;
		dest6.sin6_port = htons(4342);
		inet_pton(AF_INET6, MAP_RESOLVER6, &dest6.sin6_addr);

		dest = &dest6;
		dest_size = sizeof(dest6);

	}else if(CONTROL_VERSION == 4){
                struct sockaddr_in dest4;

                memset(&dest4, 0, sizeof(dest4));
                dest4.sin_family = AF_INET;
                dest4.sin_port = htons(4342);
                inet_pton(AF_INET, MAP_RESOLVER4, &dest4.sin_addr);

		dest = &dest4;
                dest_size = sizeof(dest4);
	}

	ipv4_create_request_packet(&req, sizeof(req), (char *)&(lisp_source4.s_addr), lisp_dest_addr, (char *)&(lisp_source4.s_addr), lisp_prefix);
	packet =  ipv4_encap_map_request(&packetsize, &req, sizeof(req), (char *)&(lisp_source4.s_addr), lisp_dest_addr);

	send_size = sendto(udp_sock, packet, packetsize, 0, (struct sockaddr *)dest, dest_size);
	if(send_size == -1){
		perror("send");
		exit(1);
	}
	printf("request message %d byte sent\n", send_size);
	free(packet);

	return 0;
}


int ipv6_send_map_request(char *lisp_dest_addr, int lisp_prefix){
	char *packet;
	struct req_mes6 req;
	int packetsize;
	int fd;
	int send_size;

        struct in6_addr lisp_source6;
        inet_pton(AF_INET6, RLOC6, &lisp_source6);

	struct timeval socket_timeout;
	void *dest;
	int dest_size;

	if(CONTROL_VERSION == 6){
		struct sockaddr_in6 dest6;

		memset(&dest6, 0, sizeof(dest6));
		dest6.sin6_family = AF_INET6;
		dest6.sin6_port = htons(4342);
		inet_pton(AF_INET6, MAP_RESOLVER6, &dest6.sin6_addr);

		dest = &dest6;
		dest_size = sizeof(dest6);
	}else if(CONTROL_VERSION == 4){
                struct sockaddr_in dest4;

                memset(&dest4, 0, sizeof(dest4));
                dest4.sin_family = AF_INET;
                dest4.sin_port = htons(4342);
                inet_pton(AF_INET, MAP_RESOLVER4, &dest4.sin_addr);

		dest = &dest4;
                dest_size = sizeof(dest4);
	}

	ipv6_create_request_packet(&req, sizeof(req), lisp_source6.s6_addr, lisp_dest_addr, lisp_source6.s6_addr, lisp_prefix);
	packet =  ipv6_encap_map_request(&packetsize, &req, sizeof(req), lisp_source6.s6_addr, lisp_dest_addr);

	send_size = sendto(udp_sock, packet, packetsize, 0, (struct sockaddr *)dest, dest_size);
	if(send_size == -1){
		perror("send");
		exit(1);
	}
	printf("request message %d byte sent\n", send_size);
	free(packet);

	return 0;
}

void *receive_control_packet(void *args){
        char buf[2000];
        int readsize;
        struct rep_mes *reply;

        while(1){

                memset(buf, 0, sizeof(buf));
                readsize = read(udp_sock, buf, sizeof(buf));
                if(readsize<0){
                        printf("read failed\n");
                        exit(1);
                }
                printf("data received %d byte.\n", readsize);

                horder(buf, readsize);
                reply = (struct rep_mes *)buf;

                if(reply->h.TYPE == 2){
                        if(reply->d.d66.EID_AFI == 2){
                                ipv6_receive_reply(buf, readsize);
                        }else if(reply->d.d66.EID_AFI == 1){
                                ipv4_receive_reply(buf, readsize);
                        }
                }
	}
}

void ipv6_receive_reply(char *buf, int readsize){
        struct rep_mes *reply;

        char result_eid[16];
        char result_rloc[16];
        int result_prefix;
        int result_af;
        int result_num;
        int result_ttl;


	memset(result_eid, 0, 16);
	memset(result_rloc, 0, 16);
       	reply = (struct rep_mes *)buf;

       	if(reply->d.d66.ACT != 0){
               	printf("Negative map-reply returned\n");
               	result_prefix = reply->d.d66.EID_MASKLEN;
               	result_ttl = reply->d.d66.TTL;
               	norder(reply->d.d66.EID_PREFIX, 16);
               	memcpy(result_eid, reply->d.d66.EID_PREFIX, 16);



                if(ipv6_rem_list_by_nonce(reply->h.NONCE)){
	                printf("removed temporary route and registered parmanent route\n");

                        printf("regist negative cache prefix = %d\n", result_prefix);
			regist_prefix(2, result_eid, result_prefix, result_rloc, 0);

                        /* regist route info */
                        struct info *newroute = malloc(sizeof(struct info));
                        memset(newroute, 0, sizeof(struct info));
                        memcpy(newroute->address, result_eid, 16);
                        newroute->state = STATE_TTL;
                        newroute->prefix = result_prefix;
                        newroute->ttl = result_ttl * 60;
                        ipv6_add_list(newroute);
		}


       	}else{

		if(reply->d.d66.LOC_AFI == 2){
			printf("COUNT = %d, EID = IPv6, LOC = IPv6\n", reply->h.REC_COUNT);

			norder(reply->d.d66.EID_PREFIX, 16);
			norder(reply->d.d66.LOCATOR, 16);
			printf("EID prefix is %d\n", reply->d.d66.EID_MASKLEN);

			memcpy(result_rloc, reply->d.d66.LOCATOR, 16);
			memcpy(result_eid, reply->d.d66.EID_PREFIX, 16);
			result_prefix = reply->d.d66.EID_MASKLEN;
			result_af = 2;
			result_ttl = reply->d.d66.TTL;
		}else{
			printf("COUNT = %d, EID = IPv6, LOC = IPv4\n", reply->h.REC_COUNT);

			norder(reply->d.d64.EID_PREFIX, 16);
			norder(reply->d.d64.LOCATOR, 4);
			printf("EID prefix is %d\n", reply->d.d64.EID_MASKLEN);

			memcpy(result_rloc, reply->d.d64.LOCATOR, 4);
			memcpy(result_eid, reply->d.d64.EID_PREFIX, 16);
			result_prefix = reply->d.d64.EID_MASKLEN;
			result_af = 1;
			result_ttl = reply->d.d64.TTL;
		}



                if(ipv6_rem_list_by_nonce(reply->h.NONCE)){
                        printf("removed temporary route and registered parmanent route\n");

                        regist_prefix(2, result_eid, result_prefix, result_rloc, result_af);

                        /* regist route info */
                        struct info *newroute = malloc(sizeof(struct info));
                        memset(newroute, 0, sizeof(struct info));
                        memcpy(newroute->address, result_eid, 16);
                        newroute->state = STATE_TTL;
                        newroute->prefix = result_prefix;
                        newroute->ttl = result_ttl * 60;
                        ipv6_add_list(newroute);
                }
	}
}

void ipv4_receive_reply(char *buf, int readsize){
        struct rep_mes *reply;

        char result_eid[16];
        char result_rloc[16];
        int result_prefix;
        int result_af;
        int result_num;
        int result_ttl;

        memset(result_eid, 0, 16);
        memset(result_rloc, 0, 16);
    	reply = (struct rep_mes *)buf;

       	if(reply->d.d46.ACT != 0){
               	printf("Negative map-reply returned\n");
               	result_prefix = reply->d.d46.EID_MASKLEN;
               	result_ttl = reply->d.d46.TTL;
               	norder(reply->d.d46.EID_PREFIX, 4);
               	memcpy(result_eid, reply->d.d46.EID_PREFIX, 4);


                if(ipv4_rem_list_by_nonce(reply->h.NONCE)){
 	               printf("removed temporary route and registered parmanent route\n");

                        /* negative cache is returned */
                        printf("regist negative cache prefix = %d\n", result_prefix);
                        regist_prefix(1, result_eid, result_prefix, result_rloc, 0);

                        /* regist route info */
                        struct info *newroute = malloc(sizeof(struct info));
                        memset(newroute, 0, sizeof(struct info));
                        memcpy(newroute->address, result_eid, 16);
                        newroute->state = STATE_TTL;
                        newroute->prefix = result_prefix;
                        newroute->ttl = result_ttl * 60;
                        ipv4_add_list(newroute);
                }

	}else{

	       	if(reply->d.d46.LOC_AFI == 2){
			printf("COUNT = %d, EID = IPv4, LOC = IPv6\n", reply->h.REC_COUNT);

                	norder(reply->d.d46.EID_PREFIX, 4);
			norder(reply->d.d46.LOCATOR, 16);
                	printf("EID prefix is %d\n", reply->d.d46.EID_MASKLEN);

                	memcpy(result_rloc, reply->d.d46.LOCATOR, 16);
			memcpy(result_eid, reply->d.d46.EID_PREFIX, 4);
			result_prefix = reply->d.d46.EID_MASKLEN;
			result_af = 2;
			result_ttl = reply->d.d46.TTL;
       		}else{
			printf("COUNT = %d, EID = IPv4, LOC = IPv4\n", reply->h.REC_COUNT);

			norder(reply->d.d44.EID_PREFIX, 4);
			norder(reply->d.d44.LOCATOR, 4);
			printf("EID prefix is %d\n", reply->d.d44.EID_MASKLEN);

			memcpy(result_rloc, reply->d.d44.LOCATOR, 4);
			memcpy(result_eid, reply->d.d44.EID_PREFIX, 4);
			result_prefix = reply->d.d44.EID_MASKLEN;
			result_af = 1;
			result_ttl = reply->d.d44.TTL;
       		}

                if(ipv4_rem_list_by_nonce(reply->h.NONCE)){
			printf("removed temporary route and registered parmanent route\n");

                        regist_prefix(1, result_eid, result_prefix, result_rloc, result_af);

                        /* regist route info */
			struct info *newroute = malloc(sizeof(struct info));
			memset(newroute, 0, sizeof(struct info));
			memcpy(newroute->address, result_eid, 16);
			newroute->state = STATE_TTL;
			newroute->prefix = result_prefix;
			newroute->ttl = result_ttl * 60;
			ipv4_add_list(newroute);
                }
	}
}

void *ipv6_check_request_queue(void *arg){
	char destination[16];

	/* initiate IPv6 map-request thread */
	if(pthread_mutex_lock(&mutex_reqv6) != 0){
		printf("pthread: map-request: lock failed\n");
		exit(1);
	}

	while(1){
		if(check_queue(&ipv6_queue_start) == 1){

			/* lock IPv6 queue mutex */
			if(pthread_mutex_lock(&mutex_queuev6) != 0){
				printf("pthread: queuev6: lock failed\n");
				exit(1);
			}

			dequeue(&ipv6_queue_start, destination);

			/* unlock IPv6 queue mutex */
                        if(pthread_mutex_unlock(&mutex_queuev6) != 0){
                                printf("pthread: queuev6: unlock failed\n");
                                exit(1);
                        }

			ipv6_send_map_request(destination, 128);
		}else{
			/* wait to next map-request */
			if(pthread_cond_wait(&cond_reqv6, &mutex_reqv6) != 0){
      				printf("pthread: map-request: wait failed\n");
				exit(1);
			}
		}
	}
}

void *ipv4_check_request_queue(void *arg){
	char destination[16];

	/* initiate IPv4 map-request thread */
	if(pthread_mutex_lock(&mutex_reqv4) != 0){
		printf("pthread: map-request: lock failed\n");
		exit(1);
	}

	while(1){
		if(check_queue(&ipv4_queue_start) == 1){

			/* lock IPv4 queue mutex */
			if(pthread_mutex_lock(&mutex_queuev4) != 0){
				printf("pthread: queuev4: lock failed\n");
				exit(1);
			}

			dequeue(&ipv4_queue_start, destination);

			/* unlock IPv4 queue mutex */
                        if(pthread_mutex_unlock(&mutex_queuev4) != 0){
                                printf("pthread: queuev4: unlock failed\n");
                                exit(1);
                        }

			ipv4_send_map_request(destination, 32);
		}else{
			/* wait to next map-request */
			if(pthread_cond_wait(&cond_reqv4, &mutex_reqv4) != 0){
      				printf("pthread: map-request: wait failed\n");
				exit(1);
			}
		}
	}
}

