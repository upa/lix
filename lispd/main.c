#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/if.h>  
#include <linux/if_tun.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <syslog.h>

#include "main.h"
#include "utils.h"
#include "route.h"
#include "request.h"
#include "register.h"
#include "queue.h"
#include "netlink.h"
#include "parser.h"
#include "cli.h"
#include "reply.h"

pthread_t thread_id_recv;
pthread_t thread_id_ipv4_ttl;
pthread_t thread_id_ipv6_ttl;
pthread_t thread_id_netlink;

/* for register thread */
pthread_t thread_id_reg;
pthread_mutex_t mutex_reg = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_reg =  PTHREAD_COND_INITIALIZER;

/* for IPv4 map-request */
pthread_t thread_id_reqv4;
pthread_mutex_t mutex_queuev4 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_reqv4 = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_reqv4 =  PTHREAD_COND_INITIALIZER;

/* for IPv6 map-request */
pthread_t thread_id_reqv6;
pthread_mutex_t mutex_queuev6 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_reqv6 = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_reqv6 =  PTHREAD_COND_INITIALIZER;

struct queue_item ipv4_queue_start;
struct queue_item ipv6_queue_start;

struct config config_root;
struct state_list states_root;

int udp_sock;
int port_num;
int netlink_sock;
int control_version;
int default_ttl;
int syslog_facility;
char authentication_key[256];
char config_path[1024];
char *optarg;

void cleanup_signal(int sig){
	close(udp_sock);
	close(netlink_sock);
        exit (0);
}

void usage(){
	printf("\n");
	printf(" usage:\n");
	printf("\tlisp -d\n");
	printf("\n");
	printf(" option:\n");
	printf("\t-h: Show help.\n");
	printf("\t-d: Run as a daemon.\n");
	printf("\t-c: Set config file path");
	printf("\n");

	return;
}

void setup_syslog_facility(char *config){
	if(!strcmp(config, "local0")){
		syslog_facility = LOG_LOCAL0;
	}else if(!strcmp(config, "local1")){
		syslog_facility = LOG_LOCAL1;
	}else if(!strcmp(config, "local2")){
		syslog_facility = LOG_LOCAL2;
	}else if(!strcmp(config, "local3")){
		syslog_facility = LOG_LOCAL3;
	}else if(!strcmp(config, "local4")){
		syslog_facility = LOG_LOCAL4;
	}else if(!strcmp(config, "local5")){
		syslog_facility = LOG_LOCAL5;
	}else if(!strcmp(config, "local6")){
		syslog_facility = LOG_LOCAL6;
	}else if(!strcmp(config, "local7")){
		syslog_facility = LOG_LOCAL7;
	}else{
		syslog_facility = LOG_DAEMON;
	}
}

int main (int argc, char * argv[]){
	int ch;
	int d_flag = 0;
	int c_flag = 0;
	struct sockaddr_in6 me;
	int sock_size;
	struct sockaddr_nl s_nladdr;
	int send_map_register_or_not;

	while ((ch = getopt (argc, argv, "hdc:")) != -1) {
		switch (ch) {
			case 'h' :
				usage ();
				return 0;
				break;

			case 'd' :
				d_flag = 1;
				break;

			case 'c' :
				if(optarg == NULL){
					err (EXIT_FAILURE, "please set config file path after -c option");
				}else{
					strcpy(config_path, optarg);
					c_flag = 1;
				}

				break;

			default :
				break;
			}
	}
	if(c_flag == 0){
		err (EXIT_FAILURE, "please set config file path after -c option");
	}

        if (signal (SIGINT, cleanup_signal)  == SIG_ERR)
                err (EXIT_FAILURE, "failt to register SIGINT");

        if (signal (SIGTERM, cleanup_signal)  == SIG_ERR){
                err (EXIT_FAILURE, "failt to register SIGTERM");
        }

        memset(&states_root, 0, sizeof(struct state_list));
        memset(&config_root, 0, sizeof(struct config));
        flush_config(&config_root, &states_root);
	parse_config(&config_root, &states_root);

        struct config *root_config = (struct config *)&config_root;
        struct root_layer_data *root_data = (struct root_layer_data *)(root_config->data);
	send_map_register_or_not = root_data->send_map_register;
	default_ttl = root_data->default_ttl;
	control_version = root_data->control_ip_version;
	memset(authentication_key, 0, 256);
	strcpy(authentication_key, root_data->authentication_key);
	setup_syslog_facility(root_data->syslog_facility);

	/* run as a daemon */
        if (d_flag > 0) {
                if (daemon (0, 1) != 0)
                        err (EXIT_FAILURE, "fail to run as a daemon\n");
        }

        /* dualstack control-plane socket */
        memset(&me, 0, sizeof(me));
        me.sin6_family = AF_INET6;
        me.sin6_addr = in6addr_any;

        udp_sock = ipv6_create_sock();
        if(udp_sock < 0) {
		err(EXIT_FAILURE, "socket");
        }

        if(bind(udp_sock, (struct sockaddr *)&me, sizeof(me)) < 0){
		err(EXIT_FAILURE, "ipv6 bind");
        }

	sock_size = sizeof(me);
	if(getsockname(udp_sock, (struct sockaddr *)&me, &sock_size) < 0){
		err(EXIT_FAILURE, "getsockname");
	}
	port_num = ntohs(me.sin6_port);

        /* start ipv4 map-request service */
        if (pthread_create(&thread_id_reqv4, NULL, ipv4_check_request_queue, NULL) != 0 ){
                exit(1);
        }

        /* start ipv6 map-request service */
        if (pthread_create(&thread_id_reqv6, NULL, ipv6_check_request_queue, NULL) != 0 ){
                exit(1);
        }

	if(send_map_register_or_not == 1){
		/* initiate register thread */
		if(pthread_mutex_lock(&mutex_reg) != 0){
			err(EXIT_FAILURE, "pthread: register: lock failed");
		}

		/* start sending map-regist */
		if (pthread_create(&thread_id_reg, NULL, start_map_register, NULL) != 0 ){ 
			exit(1);  
		}  

		/* wait to cleanup register */
		if(pthread_cond_wait(&cond_reg, &mutex_reg) != 0){
			err(EXIT_FAILURE, "pthread: register: wait failed");
		}

		/* finalize initiation */
		if(pthread_mutex_unlock(&mutex_reg) != 0){
			err(EXIT_FAILURE, "pthread: register: unlock failed");
		}
	}

        /* start receiving reply */
        if (pthread_create(&thread_id_recv, NULL, receive_response_packet, NULL) != 0 ){
                exit(1);
        }

        /* start IPv4 TTL timer */
        if (pthread_create(&thread_id_ipv4_ttl, NULL, ipv4_rem_list_by_ttl, NULL) != 0 ){
                exit(1);
        }

        /* start IPv6 TTL timer */
        if (pthread_create(&thread_id_ipv6_ttl, NULL, ipv6_rem_list_by_ttl, NULL) != 0 ){
                exit(1);
        }

        netlink_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_LISP);

        /* source address */
        memset(&s_nladdr, 0, sizeof(s_nladdr));
        s_nladdr.nl_family = AF_NETLINK;
        s_nladdr.nl_pad = 0;
        s_nladdr.nl_pid = getpid();
	s_nladdr.nl_groups = NETLINK_GROUP;
        bind(netlink_sock, (struct sockaddr*)&s_nladdr, sizeof(s_nladdr));

        /* start netlink receiver */
        if (pthread_create(&thread_id_netlink, NULL, netlink_receive_request, NULL) != 0 ){
                exit(1);
        }

	flush_route(1);
	flush_route(2);

	ipv6_regist_static_routes();
	ipv4_regist_static_routes();

	wait_telnet();
	return 0;
}
