struct reg_header {
	__u32		REC_COUNT : 8,
			RESERVED : 19,
			P : 1,
			TYPE : 4;
	char		NONCE[8];
	__u32		AUTH_DATA_LENGTH : 16,
			KEY_ID : 16;
	char		AUTH_DATA[SHA_DIGEST_LENGTH];
};

struct reg_data6 {
	__u32		TTL,
			RESERVED : 12,
			A : 1,
			ACT : 3,
			EID_MASKLEN : 8,
			LOC_COUNT : 8,
			EID_AFI : 16,
			MAP_VERSION_NUM : 12,
			RSVD : 4;
	char		EID_PREFIX[16];
	__u32		M_WEIGHT : 8,
			M_PRIORITY : 8,
			WEIGHT : 8,
			PRIORITY : 8,
			LOC_AFI : 16,
			R : 1,
			P : 1,
			L : 1,
			UNUSED_FLAGS : 13;
	char		LOCATER[16];
};

struct reg_data4 {
        __u32           TTL,
                        RESERVED : 12,
                        A : 1,
                        ACT : 3,
                        EID_MASKLEN : 8,
                        LOC_COUNT : 8,
                        EID_AFI : 16,
                        MAP_VERSION_NUM : 12,
                        RSVD : 4;
        char            EID_PREFIX[4];
        __u32           M_WEIGHT : 8,
                        M_PRIORITY : 8,
                        WEIGHT : 8,
                        PRIORITY : 8,
                        LOC_AFI : 16,
                        R : 1,
                        P : 1,
                        L : 1,
                        UNUSED_FLAGS : 13;
        char            LOCATER[4];
};

struct prefixes {
	struct prefixes *next;
	char eid[100];
	int prefix;
	int version;
};

void hmac(char *md, void *buf, size_t size);
char *create_register_packet(int *packet_size, struct prefixes *start, int rflag);
void ipv4_create_register_data(struct reg_data4 *data, int rflag, char *eid, int prefix);
void ipv6_create_register_data(struct reg_data6 *data, int rflag, char *eid, int prefix);
void *send_map_register(void *arg);

