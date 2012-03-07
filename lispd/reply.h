#pragma pack(1)
struct reply_header {
#if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t	reserved1:1,
			security_bit:1,
			enabled_bit:1,
			probe_bit:1,
			type:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t	type:4,
			probe_bit:1,
			enabled_bit:1,
			probe_bit:1,
			reserved1:1;
#endif
	uint16_t	reserved2;
	uint8_t		record_count;
	uint32_t	nonce[2];
};
#pragma pack()

struct reply_record_header {
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
	uint32_t	map_version1:4,
			reserved3:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	uint32_t	reserved3:4,
			map_version1:4;
#endif
	uint8_t		map_version2;
	uint16_t	eid_prefix_afi;
};

struct reply_locator_header {
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

struct reply_header_attr {
	unsigned int	nonce[2];
};

struct reply_record_attr {
	unsigned int	record_ttl;
	int 		act;
};

struct reply_locator_attr {
	int		priority;
	int		weight;
};

void *receive_response_packet(void *args);
int parse_reply_header(char *buf, int *offset, int *record_count, struct reply_header_attr *header_attr);
int parse_reply_record_header(char *buf, int *offset, int *locator_count, struct record *eid);
int parse_reply_locator_header(char *buf, int *offset, struct record *locators);
int add_reply_cache(struct reply_header_attr *attr, struct record *eid, struct record *locators);
int receive_reply(char *buf, int size);
