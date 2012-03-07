
struct register_header {
#if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t	reserved1:3,
			proxy_bit:1,
			type:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t	type:4,
			proxy_bit:1,
			reserved1:3;
#endif
	uint8_t		reserved2;
#if BYTE_ORDER == LITTLE_ENDIAN
        uint32_t	notify_bit:1,
			reserved3:7;
#endif
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        reserved3:7,
                        notify_bit:1;
#endif
	uint8_t		record_count;
	uint32_t	nonce[2];
	uint16_t	key_id;
	uint16_t	auth_len;
};

struct register_record {
	uint32_t	record_ttl;
	uint8_t		locator_count;
	uint8_t		eid_mask_len;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t	reserved1:4,
			auth_bit:1,
			act:3;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	uint32_t	act:3,
			auth_bit:1,
			reserved1:4;
#endif
	uint8_t		reserved2;
#if BYTE_ORDER == LITTLE_ENDIAN
        uint32_t        map_version1:4,
                        reserved3:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t        reserved3:4,
                        map_version1:4;
#endif
	uint8_t		map_version2;
	uint16_t	eid_prefix_afi;
};

struct register_locator {
	uint8_t		priority;
	uint8_t		weight;
	uint8_t		m_priority;
	uint8_t		m_weight;
	uint8_t		unused_flags1;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t	route_bit:1,
			probe_bit:1,
			local_bit:1,
			unused_flags2:5;
#endif
#if BYTE_ORDER == BIG_ENDIAN
			unused_flags2:5,
			local_bit:1,
			probe_bit:1,
			route_bit:1;
#endif
	uint16_t	locator_afi;
};

/* NOT USED
struct register_header_attr {

};
*/

struct register_record_attr {
	int 		record_ttl;
	int 		act;
};

struct register_locator_attr {
	int 		priority;
	int 		weight;
};

void hmac(char *md, void *buf, size_t size);
int create_map_register_header(char *buf, int *offset, struct record *request_dest);
int create_map_register_record(char *buf, int *offset, struct record *request_dest, struct record *request_source);
int create_map_register_locator(char *buf, int *offset, struct record *request_source);
int create_map_register(char *buf, struct record *request_dest, struct record *request_source);
int send_map_register(struct record *request_dest, struct record *request_source);
void *start_map_register(void *arg);

