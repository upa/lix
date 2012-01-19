#define ROUTE_REGIST 1
#define ROUTE_DELETE 2

struct netlink_request {
	char daddr[16];
        uint32_t dest_af;
};

struct netlink_result {
	uint32_t operation;
	uint32_t af;
	char eid[16];
	uint32_t prefix;
	char rloc[16];
	uint32_t rloc_af;
};

void *netlink_receive_request(void *args);
int netlink_send_result(void *buf, int size);

