
struct lisp_hdr {
#if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t	reserved1:4,
			type:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
        uint32_t	type:4,
			reserved1:4;
#endif	
	uint8_t		reserved2;
	uint16_t	reserved3;
};

char *encapsulate_map_request(char *buf, int size, int *encapsulated_size);
