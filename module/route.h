struct route_entry {
        struct route_entry *parent;
        char nexthop[16];
	int af;
        int flag;
        struct route_entry *one;
        struct route_entry *zero;
};

int return_bit(void *addr, int prefix);
struct route_entry *regist_prefix(struct route_entry *start, char *network, int prefix, char *nexthop, int af);
int match_dst(struct route_entry *start, char *dst, char *nexthop, int *af);
int delete_prefix(struct route_entry *start, char *network, int prefix);

