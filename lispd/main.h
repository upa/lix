extern int udp_sock;
extern int netlink_sock;
extern int port_num;
extern int default_ttl;
extern int control_version;
extern char authentication_key[256];
extern int syslog_facility;
extern char * optarg;
extern char config_path[1024];

extern struct config config_root;
extern struct state_list states_root;

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

void usage();
void cleanup_sigint (int sig);
void setup_syslog_facility(char *config);

#define NETLINK_LISP 17
#define NETLINK_GROUP 1
#define PROCESS_NAME "lispd"
#define SHA_DIGEST_LENGTH 20
#define MAPREGIST_INTERVAL 60
#define MTU 1500
#define IANA_AFI_IPV4   0x0100
#define IANA_AFI_IPV6   0x0200
