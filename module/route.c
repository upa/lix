#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/version.h>

#include "main.h"
#include "route.h"

int return_bit(void *addr, int prefix){
	int i = (prefix - 1) / 32;
	int j = prefix - (i * 32);

	unsigned int temp = 1 << (32 - j);
	unsigned int *ptr = addr;
	unsigned int s = htonl(ptr[i]);

	if(s & temp){
		return 1;
	}else{
		return 0;
	}
}

struct route_entry *regist_prefix(struct route_entry *start, char *network, int prefix, char *nexthop, int af){
	int i;
	struct route_entry *ptr = start;

	for(i = 0; i <= prefix; i++){
		if(i == prefix){
			ptr->flag = 1;
			ptr->af = af;
			memcpy(ptr->nexthop, nexthop, 16);
			break;
		}

		if(return_bit(network, i + 1)){
			if(ptr->one == NULL){
				ptr->one = (struct route_entry *)kmalloc(sizeof(struct route_entry), GFP_ATOMIC);
				memset(ptr->one, 0, sizeof(struct route_entry));
				ptr->one->parent = ptr;
				ptr = ptr->one;
			}else{
				ptr = ptr->one;
			}
		}else{
			if(ptr->zero == NULL){
				ptr->zero = (struct route_entry *)kmalloc(sizeof(struct route_entry), GFP_ATOMIC);
				memset(ptr->zero, 0, sizeof(struct route_entry));
				ptr->zero->parent = ptr;
				ptr = ptr->zero;
			}else{
				ptr = ptr->zero;
			}
		}
	}

	return ptr;
}

int match_dst(struct route_entry *start, char *dst, char *nexthop, int *af){
	struct route_entry *ptr = start;
	int i = 0;
	int prefix = 0;
	*af = 0;

	while(1){
		if(return_bit(dst, i + 1)){
			if(ptr->one == NULL){
				break;
			}else{
				ptr = ptr->one;
				if(ptr->flag == 1){
					prefix = i + 1;
					memcpy(nexthop, ptr->nexthop, 16);
					*af = ptr->af;
				}
			}
		}else{
			if(ptr->zero == NULL){
				break;
			}else{
				ptr = ptr->zero;
				if(ptr->flag == 1){
					prefix = i + 1;
					memcpy(nexthop, ptr->nexthop, 16);
					*af = ptr->af;
				}
			}
		}
		i++;
	}

	return prefix;
}

int flush_route(struct route_entry *start){
	struct route_entry *ptr = start;
	struct route_entry *temp;

	while(start->one != NULL || start->zero != NULL){
		while(ptr->zero != NULL || ptr->one != NULL){
			if(ptr->zero != NULL){
				ptr = ptr->zero;
			}else if(ptr->one != NULL){
				ptr = ptr->one;
			}
		}

	        if(ptr->flag == 0){
	                printk(KERN_INFO "lisp: route: route register bug assumed!\n");
	        }else{
	                ptr->flag = 0;
	        }

	        while(ptr != start && ptr->flag == 0 && ptr->one == NULL && ptr->zero == NULL){
        	        temp = ptr;
                	ptr = ptr->parent;
                	if(temp == ptr->one){
                        	ptr->one = NULL;
                	}else{
                        	ptr->zero = NULL;
                	}
                	kfree(temp);
        	}

		ptr = start;
	}

	return 0;
}

int delete_prefix(struct route_entry *start, char *network, int prefix){
	int i;
	struct route_entry *ptr = start;
	struct route_entry *temp;

	for(i = 0; i < prefix; i++){
		if(return_bit(network, i + 1)){
			if(ptr->one != NULL){
				ptr = ptr->one;
			}else{
				printk(KERN_INFO "lisp: route: the record don't exists\n");
				return -1;
			}
		}else{
			if(ptr->zero != NULL){
				ptr = ptr->zero;
			}else{
				printk(KERN_INFO "lisp: route: the record don't exists\n");
				return -1;
			}
		}
	} 

	if(ptr->flag == 0){
		printk(KERN_INFO "lisp: route: the record don't exists\n");
		return -1;
	}else{
		ptr->flag = 0;
	}


	while(ptr != start && ptr->flag == 0 && ptr->one == NULL && ptr->zero == NULL){
		temp = ptr;
		ptr = ptr->parent;
		if(temp == ptr->one){
			ptr->one = NULL;
		}else{
			ptr->zero = NULL;
		}
		kfree(temp);
	}

	return 0;

}


