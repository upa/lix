#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <pthread.h>

#include "main.h"
#include "route.h"
#include "netlink.h"

struct info ipv4_info;
struct info ipv6_info;
pthread_mutex_t mutex_ipv4_info = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_ipv6_info = PTHREAD_MUTEX_INITIALIZER;

int regist_prefix(int af, char *network, int prefix, char *nexthop, int rloc_af){
	struct netlink_result result;

	memset(&result, 0, sizeof(result));
	result.operation = htonl(ROUTE_REGIST);
	result.af = htonl(af);
	memcpy(result.eid, network, 16);
	result.prefix = htonl(prefix);
	memcpy(result.rloc, nexthop, 16);
	result.rloc_af = htonl(rloc_af);

	netlink_send_result(&result, sizeof(result));

	return 0;
}

int delete_prefix(int af, char *network, int prefix){
	struct netlink_result result;

	memset(&result, 0, sizeof(result));
	result.operation = htonl(ROUTE_DELETE);
	result.af = htonl(af);
        memcpy(result.eid, network, 16);
        result.prefix = htonl(prefix);

	netlink_send_result(&result, sizeof(result));

	return 0;
}

void ipv4_add_list(struct info *obj){
	/* lock ipv4 info */
        if(pthread_mutex_lock(&mutex_ipv4_info) != 0){
        	printf("pthread: ttl: ipv4_info lock failed\n");
                exit(1);
        }

	obj->next = ipv4_info.next;
	ipv4_info.next = obj;

        /* unlock ipv4 info */
        if(pthread_mutex_unlock(&mutex_ipv4_info) != 0){
                printf("pthread: ttl: ipv4_info unlock failed\n");
                exit(1);
        }
}

void ipv6_add_list(struct info *obj){
        /* lock ipv6 info */
        if(pthread_mutex_lock(&mutex_ipv6_info) != 0){
                printf("pthread: ttl: ipv6_info lock failed\n");
                exit(1);
        }

        obj->next = ipv6_info.next;
        ipv6_info.next = obj;

        /* unlock ipv6 info */
        if(pthread_mutex_unlock(&mutex_ipv6_info) != 0){
                printf("pthread: ttl: ipv6_info unlock failed\n");
                exit(1);
        }
}

int ipv4_rem_list_by_nonce(char *nonce){
        struct info *ptr;
        struct info *prev;

        while(1){
                /* lock ipv4 info */
                if(pthread_mutex_lock(&mutex_ipv4_info) != 0){
                        printf("pthread: ttl: ipv4_info lock failed\n");
                        exit(1);
                }

                if(ipv4_info.next != NULL){
                        prev = &ipv4_info;
                        ptr = &ipv4_info;
                        while(ptr->next != NULL){
                                prev = ptr;
                                ptr = ptr->next;

                                if(ptr->state == STATE_NONCE){
                                        if(!memcmp(ptr->nonce, nonce, 8)){

                                                delete_prefix(1, ptr->address, ptr->prefix);

                                                prev->next = ptr->next;
                                                free(ptr);
                                                ptr = prev;

				                /* unlock ipv4 info */
				                if(pthread_mutex_unlock(&mutex_ipv4_info) != 0){
				                        printf("pthread: ttl: inv4_info unlock failed\n");
				                        exit(1);
				                }
						return 1;
                                        }
                                }
                        }
                }

                /* unlock ipv4 info */
                if(pthread_mutex_unlock(&mutex_ipv4_info) != 0){
                        printf("pthread: ttl: inv4_info unlock failed\n");
                        exit(1);
                }
		return 0;
	}
}

int ipv6_rem_list_by_nonce(char *nonce){
        struct info *ptr;
        struct info *prev;

        while(1){
                /* lock ipv6 info */
                if(pthread_mutex_lock(&mutex_ipv6_info) != 0){
                        printf("pthread: ttl: ipv6_info lock failed\n");
                        exit(1);
                }

                if(ipv6_info.next != NULL){
                        prev = &ipv6_info;
                        ptr = &ipv6_info;
                        while(ptr->next != NULL){
                                prev = ptr;
                                ptr = ptr->next;

                                if(ptr->state == STATE_NONCE){
                                        if(!memcmp(ptr->nonce, nonce, 8)){

                                                delete_prefix(2, ptr->address, ptr->prefix);

                                                prev->next = ptr->next;
                                                free(ptr);
                                                ptr = prev;

				                /* unlock ipv6 info */
				                if(pthread_mutex_unlock(&mutex_ipv6_info) != 0){
				                        printf("pthread: ttl: inv6_info unlock failed\n");
				                        exit(1);
				                }
						return 1;
                                        }
                                }
                        }
                }

                /* unlock ipv6 info */
                if(pthread_mutex_unlock(&mutex_ipv6_info) != 0){
                        printf("pthread: ttl: inv6_info unlock failed\n");
                        exit(1);
                }
		return 0;
        }  
}

void *ipv4_rem_list_by_ttl(void *args){
        struct info *ptr;
        struct info *prev;

        while(1){
                /* lock ipv4 info */
                if(pthread_mutex_lock(&mutex_ipv4_info) != 0){
                        printf("pthread: ttl: ipv4_info lock failed\n");
                        exit(1);
                }

                if(ipv4_info.next != NULL){
                        prev = &ipv4_info;
                        ptr = &ipv4_info;
                        while(ptr->next != NULL){
                                prev = ptr;
                                ptr = ptr->next;

				if(ptr->state == STATE_TTL || ptr->state == STATE_NONCE){
					if(ptr->ttl != 0xffffffff && ptr->ttl != 0){
                                		ptr->ttl--;
					}
                                	if(ptr->ttl == 0){

                                        	delete_prefix(1, ptr->address, ptr->prefix);
                                        	prev->next = ptr->next;
                                        	free(ptr);
                                        	ptr = prev;
                                	}
				}
                        }
                }

                /* unlock ipv4 info */
                if(pthread_mutex_unlock(&mutex_ipv4_info) != 0){
                        printf("pthread: ttl: inv4_info unlock failed\n");
                        exit(1);
                }

		sleep(1);
        }
}

void *ipv6_rem_list_by_ttl(void *args){
	struct info *ptr;
	struct info *prev;

        while(1){
	        /* lock ipv6 info */
                if(pthread_mutex_lock(&mutex_ipv6_info) != 0){
        	        printf("pthread: ttl: ipv6_info lock failed\n");
                        exit(1);
                }

                if(ipv6_info.next != NULL){
			prev = &ipv6_info;
			ptr = &ipv6_info;
			while(ptr->next != NULL){
				prev = ptr;
				ptr = ptr->next;

				if(ptr->state == STATE_TTL || ptr->state == STATE_NONCE){
                                        if(ptr->ttl != 0xffffffff && ptr->ttl != 0){
                                                ptr->ttl--;
                                        }
					if(ptr->ttl == 0){

                				delete_prefix(2, ptr->address, ptr->prefix);
						prev->next = ptr->next;
						free(ptr);
						ptr = prev;
					}
				}
			}
		}

                /* unlock ipv6 info */
                if(pthread_mutex_unlock(&mutex_ipv6_info) != 0){
                	printf("pthread: ttl: inv6_info unlock failed\n");
                        exit(1);
                }

		sleep(1);
        }
}


