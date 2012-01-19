#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "main.h"
#include "utils.h"
#include "queue.h"
#include "netlink.h"

void *netlink_receive_request(void *args){
        struct msghdr msg;
        struct nlmsghdr *nlh=NULL;
	struct iovec iov;
	struct netlink_request *request;
	int tryresult;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct netlink_request)));
	request = (struct netlink_request *)NLMSG_DATA(nlh);

        /*iov structure */
        iov.iov_base = (void *)nlh;
        iov.iov_len = NLMSG_SPACE(sizeof(struct netlink_request));

        /* msg */
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

	while(1){
        	memset(nlh, 0, sizeof(struct netlink_request) + sizeof(struct nlmsghdr));
        	recvmsg(netlink_sock, &msg, 0);

		if(ntohl(request->dest_af) == 1){

	                /* lock ipv4 map-request queue */
	                if(pthread_mutex_lock(&mutex_queuev4) != 0){
	                        printf("pthread: main: queuev4 lock failed\n");
	                        exit(1);
	                }

	                enqueue(&ipv4_queue_start, request->daddr);

	                /* unlock ipv4 map-request queue */
	                if(pthread_mutex_unlock(&mutex_queuev4) != 0){
	                        printf("pthread: main: queuev4 unlock failed\n");
	                        exit(1);
	                }

	                /* trylock ipv4 map-request checkthread */
	                if((tryresult = pthread_mutex_trylock(&mutex_reqv4)) == EBUSY){
	                        /* do nothing because map-request thread is working */
	                }else if(tryresult == 0){
	                        /* wake up map-request thread */

	                        /* signaling to main thread */
	                        if(pthread_cond_signal(&cond_reqv4) != 0){
	                                printf("pthread: main: queuev4 cond_signal failed\n");
	                                exit(1);
	                        }
	                        /* finalize signaling */
	                        if(pthread_mutex_unlock(&mutex_reqv4) != 0){
	                                printf("pthread: main: queuev4 unlock failed\n");
	                                exit(1);
	                        }
	                }else{
	                        printf("pthread: main: queuev4 trylock failed\n");
	                        exit(1);
	                }

		}else if(ntohl(request->dest_af) == 2){

	                /* lock ipv6 map-request queue */
	                if(pthread_mutex_lock(&mutex_queuev6) != 0){
	                        printf("pthread: main: queuev6 lock failed\n");
	                        exit(1);
	                }

	                enqueue(&ipv6_queue_start, request->daddr);


	                /* unlock ipv6 map-request queue */
	                if(pthread_mutex_unlock(&mutex_queuev6) != 0){
	                        printf("pthread: main: queuev6 unlock failed\n");
	                        exit(1);
	                }

	                /* trylock ipv6 map-request checkthread */
	                if((tryresult = pthread_mutex_trylock(&mutex_reqv6)) == EBUSY){
	                        /* do nothing because map-request thread is working */
			}else if(tryresult == 0){
	                        /* wake up map-request thread */

	                        /* signaling to main thread */
	                        if(pthread_cond_signal(&cond_reqv6) != 0){
	                                printf("pthread: main: queuev6 cond_signal failed\n");
	                                exit(1);
	                        }

	                        /* finalize signaling */
	                        if(pthread_mutex_unlock(&mutex_reqv6) != 0){
	                                printf("pthread: main: queuev6 unlock failed\n");
	                                exit(1);
	                        }
	                }else{
	                        printf("pthread: main: queuev6 trylock failed\n");
	                        exit(1);
	                }

		}
	}
}

int netlink_send_result(void *buf, int size){
	struct sockaddr_nl d_nladdr;
	struct msghdr msg;
	struct nlmsghdr *nlh=NULL;
	struct iovec iov;

	/* destination address */
	memset(&d_nladdr, 0 ,sizeof(d_nladdr));
	d_nladdr.nl_family = AF_NETLINK;
	d_nladdr.nl_pad = 0;
	d_nladdr.nl_pid = 0;/* destined to kernel */

	/* Fill the netlink message header */
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(size));
	memset(nlh , 0 , NLMSG_SPACE(size));

	memcpy(NLMSG_DATA(nlh), buf, size);

	nlh->nlmsg_len = NLMSG_SPACE(size);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 1;
	nlh->nlmsg_type = 0;

	/*iov structure */
	iov.iov_base = (void *)nlh;
	iov.iov_len = NLMSG_SPACE(size);

	/* msg */
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&d_nladdr;
	msg.msg_namelen = sizeof(d_nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sendmsg(netlink_sock, &msg, 0);

	return 0; 
}
