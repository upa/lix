
struct req_header {
	__u32		REC_COUNT : 8,
			IRC : 5,
			RESERVED : 11,
			S : 1,
			P : 1,
			M : 1,
			A : 1,
			TYPE : 4;
	char		NONCE[8];
};

struct req_data6 {
	char		S_EIDAFI_EID_RLOCAFI[20];
	char		ITR_RLOC[16];
	__u32		D_EID_AFI : 16,
			D_EID_MASKLEN : 8,
			RESERVED : 8;
	char		D_EID[16];
};

struct req_data4 {
        char            S_EIDAFI_EID_RLOCAFI[8];
        char            ITR_RLOC[4];
        __u32           D_EID_AFI : 16,
                        D_EID_MASKLEN : 8,
                        RESERVED : 8;
        char            D_EID[4];
};

struct req_mes6 {
        struct req_header       h;
        struct req_data6        d;
};

struct req_mes4 {
        struct req_header       h;
        struct req_data4        d;
};

struct rep_header {
	__u32		REC_COUNT : 8,
			RESERVED : 18,
			E : 1,
			P : 1,
			TYPE : 4;
	char		NONCE[8];
};

struct rep_data66 {
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
	char		LOCATOR[16];
};

struct rep_data64 {
        __u32           TTL,
                        RESERVED : 12,
                        A : 1,
                        ACT : 3,
                        EID_MASKLEN : 8,
                        LOC_COUNT : 8,
                        EID_AFI : 16,
                        MAP_VERSION_NUM : 12,
                        RSVD : 4;
        char            EID_PREFIX[16];
        __u32           M_WEIGHT : 8,
                        M_PRIORITY : 8,
                        WEIGHT : 8,
                        PRIORITY : 8,
                        LOC_AFI : 16,
                        R : 1,
                        P : 1,
                        L : 1,
                        UNUSED_FLAGS : 13;
        char            LOCATOR[4];
};

struct rep_data46 {
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
        char            LOCATOR[16];
};

struct rep_data44 {
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
        char            LOCATOR[4];
};

union rep_data {
	struct rep_data66	d66;
	struct rep_data64	d64;
	struct rep_data46	d46;
	struct rep_data44	d44;
};

struct rep_mes {
	struct rep_header	h;
	union rep_data		d;
};


void ipv4_create_request_packet(struct req_mes4 *req, int reqsize, char * rloc_addr, char * dest_addr, char * source_addr, int query_prefix);
void ipv6_create_request_packet(struct req_mes6 *req, int reqsize, char * rloc_addr, char * dest_addr, char * source_addr, int query_prefix);
int ipv4_send_map_request(char *lisp_dest_addr, int lisp_prefix);
int ipv6_send_map_request(char *lisp_dest_addr, int lisp_prefix);
void *ipv6_check_request_queue(void *arg);
void *ipv4_check_request_queue(void *arg);
void *receive_control_packet(void *args);
void ipv6_receive_reply(char *buf, int readsize);
void ipv4_receive_reply(char *buf, int readsize);

