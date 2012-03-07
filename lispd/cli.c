#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <err.h>

#include "route.h"
#include "main.h"
#include "cli.h"

void setnonblocking(int sock) {
	int flag = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flag | O_NONBLOCK);
}

int create_listener() {
	int listener;
	struct sockaddr_in6 me;

	if ((listener = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
		err(EXIT_FAILURE, "socket");
	}

	memset(&me, 0, sizeof(me));

	me.sin6_family = AF_INET6;
	me.sin6_addr = in6addr_any;
	me.sin6_port = htons(SERVER_PORT);

	if (bind(listener, (struct sockaddr *)&me, sizeof(me)) < 0) {
		close(listener);
		err(EXIT_FAILURE, "bind");
	}

	if (listen(listener, MAX_BACKLOG) < 0) {
		close(listener);
		err(EXIT_FAILURE, "listen");
	}

        int on = 1;
        if(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0){
		close(listener);
		err(EXIT_FAILURE, "reuseaddr");
        }

	return listener;
}

char *search_notschar(char *buffer, char *word){
	char *ptr = buffer;
	char *top = strstr(ptr, word);
	while(ptr != top){
		if(!isspace(*ptr)){
			return NULL;
		}
		ptr++;
	}
	return ptr + strlen(word);
}

int switch_reaction(int client, char *buffer){
	if(strstr(buffer, "v4cache")){
		char *ptr = buffer;

		if((ptr = search_notschar(ptr, "v4cache")) == NULL){
			write(client, "Unrecognized command\n", 21);
		}else if((ptr = search_notschar(ptr, "\n")) == NULL){
			write(client, "Unrecognized command\n", 21);
		}else{
			show_map_cache(client, 4);			
		}

	}else if(strstr(buffer, "v6cache")){
		char *ptr = buffer;

		if((ptr = search_notschar(ptr, "v6cache")) == NULL){
			write(client, "Unrecognized command\n", 21);
		}else if((ptr = search_notschar(ptr, "\n")) == NULL){
			write(client, "Unrecognized command\n", 21);
		}else{
			show_map_cache(client, 6);			
		}

	}else if(strstr(buffer, "exit") != NULL){
		char *ptr = buffer;

		if((ptr = search_notschar(ptr, "exit")) == NULL){
			write(client, "Unrecognized command\n", 21);
		}else if((ptr = search_notschar(ptr, "\n")) == NULL){
			write(client, "Unrecognized command\n", 21);
		}else{
			return -1;
		}
	}else{
		char *ptr = buffer;

		if((ptr = search_notschar(ptr, "\n")) == NULL){
			write(client, "Unrecognized command\n", 21);
		}
	}

	write(client, "> ", 2);
	return 0;
}

void wait_telnet(){
	int listener, epfd;
	struct epoll_event ev;
	struct epoll_event events[MAX_EVENTS];

	listener = create_listener();

	if((epfd = epoll_create(MAX_EVENTS)) < 0) {
		err(EXIT_FAILURE, "epoll_create");
	}

	memset(&ev, 0, sizeof ev);
	ev.events = EPOLLIN;
	ev.data.fd = listener;
	epoll_ctl(epfd, EPOLL_CTL_ADD, listener, &ev);

	while (1) {
		int i;
		int nfd = epoll_wait(epfd, events, MAX_EVENTS, -1);

		for (i = 0; i < nfd; i++) {

			if (events[i].data.fd == listener) {
				struct sockaddr_in client_addr;
				socklen_t client_addr_len = sizeof(client_addr);

				int client = accept(listener, (struct sockaddr *)&client_addr, &client_addr_len);
				if (client < 0) {
					err(EXIT_FAILURE, "accept");
				}

				setnonblocking(client);

				memset(&ev, 0, sizeof ev);
				ev.events = EPOLLIN | EPOLLET;
				ev.data.fd = client;
				epoll_ctl(epfd, EPOLL_CTL_ADD, client, &ev);

				write(client, "> ", 2);
			}else{
				char buffer[1024];

				int client = events[i].data.fd;
				memset(buffer, 0, sizeof(buffer));
				int n = read(client, buffer, sizeof(buffer));
				if (n < 0) {
					epoll_ctl(epfd, EPOLL_CTL_DEL, client, &ev);
					close(client);
					warn("read");
				}else if (n == 0) {
					epoll_ctl(epfd, EPOLL_CTL_DEL, client, &ev);
					close(client);
				}else{
					if(switch_reaction(client, buffer) < 0){
						shutdown(client, SHUT_RDWR);
						epoll_ctl(epfd, EPOLL_CTL_DEL, client, &ev);
						close(client);
					}
				}
			}
		}
	}
}

void show_map_cache(int client, int af){
	if(af == 4){
		struct info *ptr;

		/* lock ipv4 info */
		if(pthread_mutex_lock(&mutex_ipv4_info) != 0){
			err(EXIT_FAILURE, "pthread: ttl: ipv4_info lock failed");
		}

		ptr = &ipv4_info;
		while(ptr->next != NULL){
			ptr = ptr->next;
			write_route_info_v4(client, ptr);
                }

	        /* unlock ipv4 info */
	        if(pthread_mutex_unlock(&mutex_ipv4_info) != 0){
			err(EXIT_FAILURE, "pthread: ttl: ipv4_info unlock failed");
	        }
	}else if(af == 6){
		struct info *ptr;

		/* lock ipv6 info */
		if(pthread_mutex_lock(&mutex_ipv6_info) != 0){
			err(EXIT_FAILURE, "pthread: ttl: ipv6_info lock failed");
		}

		ptr = &ipv6_info;
		while(ptr->next != NULL){
			ptr = ptr->next;
			write_route_info_v6(client, ptr);
                }

	        /* unlock ipv6 info */
	        if(pthread_mutex_unlock(&mutex_ipv6_info) != 0){
			err(EXIT_FAILURE, "pthread: ttl: ipv6_info unlock failed");
	        }
	}
}

void write_route_info_v4(int client, struct info *ptr){
        char r[100];
	char s[100];
	char prefixchar[10];
	char *state;
	char buffer[1024];

	memset(buffer, 0, sizeof(buffer));
        inet_ntop(AF_INET, ptr->address, r, 100);
	if(ptr->af == 1){
		inet_ntop(AF_INET, ptr->nexthop, s, 100);
	}else if(ptr->af == 2){
		inet_ntop(AF_INET6, ptr->nexthop, s, 100);
	}else if(ptr->af == 0){
		if(ptr->state == STATE_TTL){
			strcpy(s, "NativelyForward");
		}else if(ptr->state == STATE_NONCE){
			strcpy(s, "Drop");
		}
	}

	sprintf(prefixchar, "/%d", ptr->prefix);
	strcat(r, prefixchar);

	if(ptr->state == STATE_NONCE){
		state = "TEMPORARY";
	}else if(ptr->state == STATE_TTL){
		state = "RESOLVED";
	}else if(ptr->state == STATE_STATIC){
		state = "STATIC";
	}

	sprintf(buffer, "%-40s%-40s%-8d%-8s\n", r, s, ptr->ttl, state);

        write(client, buffer, strlen(buffer));
}

void write_route_info_v6(int client, struct info *ptr){
        char r[100];
	char s[100];
	char prefixchar[10];
	char *state;
        char buffer[1024];

	memset(buffer, 0, sizeof(buffer));
        inet_ntop(AF_INET6, ptr->address, r, 100);
	if(ptr->af == 1){
		inet_ntop(AF_INET, ptr->nexthop, s, 100);
	}else if(ptr->af == 2){
		inet_ntop(AF_INET6, ptr->nexthop, s, 100);
	}else if(ptr->af == 0){
		if(ptr->state == STATE_TTL){
			strcpy(s, "NativelyForward");
		}else if(ptr->state == STATE_NONCE){
			strcpy(s, "Drop");
		}
	}
	sprintf(prefixchar, "/%d", ptr->prefix);
	strcat(r, prefixchar);

        if(ptr->state == STATE_NONCE){
                state = "TEMPORARY";
        }else if(ptr->state == STATE_TTL){
                state = "RESOLVED";
        }else if(ptr->state == STATE_STATIC){
		state = "STATIC";
	}

        sprintf(buffer, "%-40s%-40s%-8d%-8s\n", r, s, ptr->ttl, state);

        write(client, buffer, strlen(buffer));
}
