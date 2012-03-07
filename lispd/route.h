extern struct info ipv4_info;
extern struct info ipv6_info;
extern pthread_mutex_t mutex_ipv4_info;
extern pthread_mutex_t mutex_ipv6_info;

#define STATE_NONCE 1
#define STATE_TTL 2
#define STATE_STATIC 3

struct info {
	struct info *next;
	int state;
	char nonce[8];
	int ttl;
	char address[16];
	char nexthop[16];
	int af;
	int prefix;
};

int regist_prefix(int af, char *network, int prefix, char *nexthop, int rloc_af);
int delete_prefix(int af, char *network, int prefix);
int flush_route(int af);
void ipv4_add_list(struct info *obj);
void ipv6_add_list(struct info *obj);
int ipv4_rem_list_by_nonce(char *nonce);
int ipv6_rem_list_by_nonce(char *nonce);
void *ipv4_rem_list_by_ttl(void *args);
void *ipv6_rem_list_by_ttl(void *args);
void ipv6_regist_static_routes();
void ipv4_regist_static_routes();
