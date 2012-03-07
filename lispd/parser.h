#define DEFAULTTTL_COMMAND 0
#define CONTROLIPVERSION_COMMAND 1
#define SENDMAPREGISTER_COMMAND 2
#define AUTHENTICATIONKEY_COMMAND 3
#define SYSLOGFACILITY_COMMAND 4

#define EID_LAYER 0
#define RLOC_LAYER 1
#define MAPSERVER_LAYER 2
#define MAPRESOLVER_LAYER 3
#define MAPCACHE_LAYER 4

#define ROOT_LAYER_COMMAND_NUM 5
#define ROOT_LAYER_MODE_NUM 5
#define ROOT_LAYER_COMMAND \
"default-ttl",\
"control-ip-version",\
"send-map-register",\
"authentication-key",\
"syslog-facility"
#define ROOT_LAYER_MODE \
"eid",\
"rloc",\
"map-server",\
"map-resolver",\
"map-cache"

#define V6PREFIX_COMMAND 0
#define V4PREFIX_COMMAND 1

#define EID_LAYER_COMMAND_NUM 2
#define EID_LAYER_MODE_NUM 0
#define EID_LAYER_COMMAND \
"v6prefix",\
"v4prefix"
#define EID_LAYER_MODE \
""

#define V6ADDRESS_COMMAND 0
#define V4ADDRESS_COMMAND 1

#define RLOC_LAYER_COMMAND_NUM 2
#define RLOC_LAYER_MODE_NUM 0
#define RLOC_LAYER_COMMAND \
"v6address",\
"v4address"
#define RLOC_LAYER_MODE \
""

#define MAPSERVER_LAYER_COMMAND_NUM 2
#define MAPSERVER_LAYER_MODE_NUM 0
#define MAPSERVER_LAYER_COMMAND \
"v6address",\
"v4address"
#define MAPSERVER_LAYER_MODE \
""

#define MAPRESOLVER_LAYER_COMMAND_NUM 2
#define MAPRESOLVER_LAYER_MODE_NUM 0

#define MAPRESOLVER_LAYER_COMMAND \
"v6address",\
"v4address"

#define MAPRESOLVER_LAYER_MODE \
""

#define V6STATIC_COMMAND 0
#define V4STATIC_COMMAND 1

#define MAPCACHE_LAYER_COMMAND_NUM 2
#define MAPCACHE_LAYER_MODE_NUM 0

#define MAPCACHE_LAYER_COMMAND \
"v6static",\
"v4static"

#define MAPCACHE_LAYER_MODE \
""


struct address_list {
	char address[128];
	int prefix;
	char nexthop[128];
	int nexthop_af;
	struct address_list *next;
};

struct config {
	void *data;
	void **under_layers;
};

struct root_layer_data {
	int default_ttl;
	int control_ip_version;
	int send_map_register;
	char authentication_key[256];
	char syslog_facility[10];
};

struct eid_layer_data {
	struct address_list v4prefix;
	struct address_list v6prefix;
};

struct rloc_layer_data {
	struct address_list v4address;
	struct address_list v6address;
};

struct mapserver_layer_data {
	struct address_list v4address;
	struct address_list v6address;
};

struct mapresolver_layer_data {
	struct address_list v4address;
	struct address_list v6address;
};

struct mapcache_layer_data {
	struct address_list v4static;
	struct address_list v6static;
};

struct state_list {
	void *ptr;
	struct state_list *next;
};


int parse_config();
void parse_eid(FILE *fp, struct config *current_config, struct state_list *states_root);
void parse_rloc(FILE *fp, struct config *current_config, struct state_list *states_root);
void parse_mapserver(FILE *fp, struct config *current_config, struct state_list *states_root);
void parse_mapresolver(FILE *fp, struct config *current_config, struct state_list *states_root);
void parse_mapcache(FILE *fp, struct config *current_config, struct state_list *states_root);
void flush_config(struct config *config_root, struct state_list *states_root);
void add_statement_to_list(struct state_list *states_root, void *data);
struct address_list *alloc_address_list(struct address_list *root, struct state_list *states_root);
