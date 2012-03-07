
/* in little endian environment, reverse per 8bit */
struct map_request_header {
#if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t	smr_bit:1,
			probe_bit:1,
			map_data_present_bit:1,
			auth_bit:1,
			type:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t	type:4,
			auth_bit:1,
			map_data_present_bit:1,
			probe_bit:1,
			smr_bit:1;
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t	reserved1:6,
			invoked_bit:1,
			pitr_bit:1;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	uint32_t	pitr_bit:1,
			invoked_bit:1,
			reserved1:6;
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t	irc:5,
			reserved2:3;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	uint32_t	reserved2:3,
			irc:5;
#endif
	uint8_t		record_count;
	uint32_t	nonce[2];
};

struct map_request_source_eid {
	uint16_t		source_eid_afi;
};

struct map_request_itr_rloc {
	uint16_t		itr_rloc_afi;
};

struct map_request_record {
	uint8_t			reserved;
	uint8_t			eid_mask_len;
	uint16_t		eid_prefix_afi;
};

int create_map_request_header(int *offset, char *buffer, struct record *request_dest, struct record *rloc_record);
int create_map_request_source_eid(int *offset, char *buffer, struct record *request_source);
int create_map_request_rloc(int *offset, char *buffer, struct record *rloc_record);
int create_map_request_eid(int *offset, char *buffer, struct record *request_dest);
int create_map_request(char *buffer, struct record *request_source, struct record *request_dest);
int send_map_request(struct record *request_source, struct record *request_dest);
void *ipv6_check_request_queue(void *arg);
void *ipv4_check_request_queue(void *arg);
