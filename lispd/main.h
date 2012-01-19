extern int udp_sock;
extern int netlink_sock;
extern int port_num;

/* for register thread */
extern pthread_mutex_t mutex_reg;
extern pthread_cond_t cond_reg;

/* for IPv4 map-request */
extern pthread_mutex_t mutex_queuev4;
extern pthread_mutex_t mutex_reqv4;
extern pthread_cond_t cond_reqv4;

/* for IPv6 map-request */
extern pthread_mutex_t mutex_queuev6;
extern pthread_mutex_t mutex_reqv6;
extern pthread_cond_t cond_reqv6;

extern struct queue_item ipv4_queue_start;
extern struct queue_item ipv6_queue_start;

void cleanup_sigint (int sig);

#define NETLINK_LISP 17
#define NETLINK_GROUP 1

#define EID6 "2001:0200:0000:88a6::"
#define PREFIX6 64
#define RLOC6 "2001:200:0:8801:203:178:143:97"

#define EID4 "153.16.68.128"
#define PREFIX4 25
#define RLOC4 "203.178.143.97"

#define MAP_SERVER6 "2001:200:0:1005:203:178:139:68"
#define MAP_SERVER4 "203.178.139.68"
#define AUTH_KEY "marutaka"
#define SHA_DIGEST_LENGTH 20

#define MAP_RESOLVER6 "2001:200:0:1005:203:178:139:68"
#define MAP_RESOLVER4 "203.178.139.68"
#define DEFAULT_TTL 60 

#define CONTROL_VERSION 4
