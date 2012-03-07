#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <err.h>

#include <pthread.h>

#include "main.h"
#include "route.h"
#include "netlink.h"
#include "parser.h"

struct info ipv4_info;
struct info ipv6_info;
pthread_mutex_t mutex_ipv4_info = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_ipv6_info = PTHREAD_MUTEX_INITIALIZER;

void ipv6_regist_static_routes(){
	struct config *mapcache_config = (struct config *)config_root.under_layers[MAPCACHE_LAYER];
	if(mapcache_config == NULL){
		return;
	}
	struct mapcache_layer_data *mapcache_data = (struct mapcache_layer_data *)(mapcache_config->data);

	struct address_list *addr_list = &(mapcache_data->v6static);
	if(addr_list->next != NULL){
		do{
			char eid[16];
			char rloc[16];
			addr_list = addr_list->next;

			inet_pton(AF_INET6, addr_list->address, eid);
			if(addr_list->nexthop_af == 1){
				inet_pton(AF_INET, addr_list->nexthop, rloc);
			}else if(addr_list->nexthop_af == 2){
				inet_pton(AF_INET6, addr_list->nexthop, rloc);
			}
			
			regist_prefix(2, eid, addr_list->prefix, rloc, addr_list->nexthop_af);

			/* regist route info */
			struct info *newroute = malloc(sizeof(struct info));
			memset(newroute, 0, sizeof(struct info));
			memcpy(newroute->address, eid, 16);
			memcpy(newroute->nexthop, rloc, 16);
			newroute->state = STATE_STATIC;
			newroute->prefix = addr_list->prefix;
			newroute->ttl = 0;
			newroute->af = addr_list->nexthop_af;
			ipv6_add_list(newroute);

		}while(addr_list->next != NULL);
	}
}

void ipv4_regist_static_routes(){
	struct config *mapcache_config = (struct config *)config_root.under_layers[MAPCACHE_LAYER];
	if(mapcache_config == NULL){
		return;
	}
	struct mapcache_layer_data *mapcache_data = (struct mapcache_layer_data *)(mapcache_config->data);

	struct address_list *addr_list = &(mapcache_data->v4static);
	if(addr_list->next != NULL){
		do{
			char eid[16];
			char rloc[16];
			addr_list = addr_list->next;

			inet_pton(AF_INET, addr_list->address, eid);
			if(addr_list->nexthop_af == 1){
				inet_pton(AF_INET, addr_list->nexthop, rloc);
			}else if(addr_list->nexthop_af == 2){
				inet_pton(AF_INET6, addr_list->nexthop, rloc);
			}
			
			regist_prefix(1, eid, addr_list->prefix, rloc, addr_list->nexthop_af);

			/* regist route info */
			struct info *newroute = malloc(sizeof(struct info));
			memset(newroute, 0, sizeof(struct info));
			memcpy(newroute->address, eid, 16);
			memcpy(newroute->nexthop, rloc, 16);
			newroute->state = STATE_STATIC;
			newroute->prefix = addr_list->prefix;
			newroute->ttl = 0;
			newroute->af = addr_list->nexthop_af;
			ipv4_add_list(newroute);

		}while(addr_list->next != NULL);
	}
}

int regist_prefix(int af, char *network, int prefix, char *nexthop, int rloc_af){
	struct netlink_result result;

	memset(&result, 0, sizeof(result));
	result.operation = htonl(ROUTE_REGIST);
	result.af = htonl(af);
	memcpy(result.eid, network, 16);
	result.prefix = htonl(prefix);
	result.rloc_af = htonl(rloc_af);

	if(nexthop == NULL){
		memset(result.rloc, 0, 16);
	}else{
		memcpy(result.rloc, nexthop, 16);
	}

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

int flush_route(int af){
	struct netlink_result result;

	memset(&result, 0, sizeof(result));
	result.operation = htonl(ROUTE_FLUSH);
	result.af = htonl(af);
	netlink_send_result(&result, sizeof(result));

	return 0;
}

void ipv4_add_list(struct info *obj){
	struct info *ptr;
	struct info *prev;
	struct info *temp;

	/* for syslog */
	char log_eid_addr[100];
	char log_rloc_addr[100];
	inet_ntop(AF_INET, obj->address, log_eid_addr, 100);
	if(obj->af == 1){
		inet_ntop(AF_INET, obj->nexthop, log_rloc_addr, 100);
	}else if(obj->af == 2){
		inet_ntop(AF_INET6, obj->nexthop, log_rloc_addr, 100);
	}else if(obj->af == 0){
		if(obj->state == STATE_TTL){
			strcpy(log_rloc_addr, "NativelyForward");
		}else if(obj->state == STATE_NONCE){
			strcpy(log_rloc_addr, "Drop");
		}
	}
	syslog_write(LOG_INFO, "added cache: %s/%d -> %s", log_eid_addr, obj->prefix, log_rloc_addr);

	/* lock ipv4 info */
        if(pthread_mutex_lock(&mutex_ipv4_info) != 0){
		err(EXIT_FAILURE, "pthread: ttl: ipv4_info lock failed");
        }

	ptr = &ipv4_info;
	prev = &ipv4_info;
	while(ptr->next != NULL){
		ptr = ptr->next;
		if(!memcmp(ptr->address, obj->address, 4) && ptr->prefix == obj->prefix){
			prev->next = ptr->next;
			temp = ptr;
			ptr = prev;
			free(temp);
		}
		prev = ptr;
	}

	obj->next = ipv4_info.next;
	ipv4_info.next = obj;

        /* unlock ipv4 info */
        if(pthread_mutex_unlock(&mutex_ipv4_info) != 0){
		err(EXIT_FAILURE, "pthread: ttl: ipv4_info unlock failed");
        }
}

void ipv6_add_list(struct info *obj){
	struct info *ptr;
	struct info *prev;
	struct info *temp;

	/* for syslog */
	char log_eid_addr[100];
	char log_rloc_addr[100];
	inet_ntop(AF_INET6, obj->address, log_eid_addr, 100);
	if(obj->af == 1){
		inet_ntop(AF_INET, obj->nexthop, log_rloc_addr, 100);
	}else if(obj->af == 2){
		inet_ntop(AF_INET6, obj->nexthop, log_rloc_addr, 100);
	}else if(obj->af == 0){
		if(obj->state == STATE_TTL){
			strcpy(log_rloc_addr, "NativelyForward");
		}else if(obj->state == STATE_NONCE){
			strcpy(log_rloc_addr, "Drop");
		}
	}
	syslog_write(LOG_INFO, "added cache: %s/%d -> %s", log_eid_addr, obj->prefix, log_rloc_addr);


        /* lock ipv6 info */
        if(pthread_mutex_lock(&mutex_ipv6_info) != 0){
		err(EXIT_FAILURE, "pthread: ttl: ipv6_info lock failed");
        }

	ptr = &ipv6_info;
	prev = &ipv6_info;
	while(ptr->next != NULL){
		ptr = ptr->next;
		if(!memcmp(ptr->address, obj->address, 16) && ptr->prefix == obj->prefix){
			prev->next = ptr->next;
			temp = ptr;
			ptr = prev;
			free(temp);
		}
		prev = ptr;
	}

        obj->next = ipv6_info.next;
        ipv6_info.next = obj;

        /* unlock ipv6 info */
        if(pthread_mutex_unlock(&mutex_ipv6_info) != 0){
		err(EXIT_FAILURE, "pthread: ttl: ipv6_info unlock failed");
        }
}

int ipv4_rem_list_by_nonce(char *nonce){
        struct info *ptr;
        struct info *prev;

        while(1){
                /* lock ipv4 info */
                if(pthread_mutex_lock(&mutex_ipv4_info) != 0){
			err(EXIT_FAILURE, "pthread: ttl: ipv4_info lock failed");
                }

                if(ipv4_info.next != NULL){
                        prev = &ipv4_info;
                        ptr = &ipv4_info;
                        while(ptr->next != NULL){
                                prev = ptr;
                                ptr = ptr->next;

                                if(ptr->state == STATE_NONCE){
                                        if(!memcmp(ptr->nonce, nonce, 8)){
						/* for syslog */
						char log_eid_addr[100];
						inet_ntop(AF_INET, ptr->address, log_eid_addr, 100);
						syslog_write(LOG_INFO, "removed temporary cache: %s/%d", log_eid_addr, ptr->prefix);

                                                delete_prefix(1, ptr->address, ptr->prefix);

                                                prev->next = ptr->next;
                                                free(ptr);
                                                ptr = prev;

				                /* unlock ipv4 info */
				                if(pthread_mutex_unlock(&mutex_ipv4_info) != 0){
							err(EXIT_FAILURE, "pthread: ttl: ipv4_info unlock failed");
				                }
						return 1;
                                        }
                                }
                        }
                }

                /* unlock ipv4 info */
                if(pthread_mutex_unlock(&mutex_ipv4_info) != 0){
			err(EXIT_FAILURE, "pthread: ttl: ipv4_info unlock failed");
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
			err(EXIT_FAILURE, "pthread: ttl: ipv6_info lock failed");
                }

                if(ipv6_info.next != NULL){
                        prev = &ipv6_info;
                        ptr = &ipv6_info;
                        while(ptr->next != NULL){
                                prev = ptr;
                                ptr = ptr->next;

                                if(ptr->state == STATE_NONCE){
                                        if(!memcmp(ptr->nonce, nonce, 8)){
						/* for syslog */
						char log_eid_addr[100];
						inet_ntop(AF_INET6, ptr->address, log_eid_addr, 100);
						syslog_write(LOG_INFO, "removed temporary cache: %s/%d", log_eid_addr, ptr->prefix);

                                                delete_prefix(2, ptr->address, ptr->prefix);

                                                prev->next = ptr->next;
                                                free(ptr);
                                                ptr = prev;

				                /* unlock ipv6 info */
				                if(pthread_mutex_unlock(&mutex_ipv6_info) != 0){
							err(EXIT_FAILURE, "pthread: ttl: ipv6_info unlock failed");
				                }
						return 1;
                                        }
                                }
                        }
                }

                /* unlock ipv6 info */
                if(pthread_mutex_unlock(&mutex_ipv6_info) != 0){
			err(EXIT_FAILURE, "pthread: ttl: ipv6_info unlock failed");
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
			err(EXIT_FAILURE, "pthread: ttl: ipv4_info lock failed");
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
						/* for syslog */
						char log_eid_addr[100];
						char log_rloc_addr[100];
						inet_ntop(AF_INET, ptr->address, log_eid_addr, 100);
						if(ptr->af == 1){
							inet_ntop(AF_INET, ptr->nexthop, log_rloc_addr, 100);
						}else if(ptr->af == 2){
							inet_ntop(AF_INET6, ptr->nexthop, log_rloc_addr, 100);
						}else if(ptr->af == 0){
							if(ptr->state == STATE_TTL){
								strcpy(log_rloc_addr, "NativelyForward");
							}else if(ptr->state == STATE_NONCE){
								strcpy(log_rloc_addr, "Drop");
							}
						}
						syslog_write(LOG_INFO, "removed cache by ttl: %s/%d -> %s", log_eid_addr, ptr->prefix, log_rloc_addr);

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
			err(EXIT_FAILURE, "pthread: ttl: ipv4_info unlock failed");
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
			err(EXIT_FAILURE, "pthread: ttl: ipv6_info lock failed");
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
						/* for syslog */
						char log_eid_addr[100];
						char log_rloc_addr[100];
						inet_ntop(AF_INET6, ptr->address, log_eid_addr, 100);
						if(ptr->af == 1){
							inet_ntop(AF_INET, ptr->nexthop, log_rloc_addr, 100);
						}else if(ptr->af == 2){
							inet_ntop(AF_INET6, ptr->nexthop, log_rloc_addr, 100);
						}else if(ptr->af == 0){
							if(ptr->state == STATE_TTL){
								strcpy(log_rloc_addr, "NativelyForward");
							}else if(ptr->state == STATE_NONCE){
								strcpy(log_rloc_addr, "Drop");
							}
						}
						syslog_write(LOG_INFO, "removed cache by ttl: %s/%d -> %s", log_eid_addr, ptr->prefix, log_rloc_addr);

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
			err(EXIT_FAILURE, "pthread: ttl: ipv4_info unlock failed");
                }

		sleep(1);
        }
}


