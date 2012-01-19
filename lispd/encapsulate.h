struct lisp_header6 {
	__u32		RESERVED : 28,
			TYPE : 4,
			FLOW_LABEL : 20,
			TRAFFIC_CLASS : 8,
			VERSION : 4,
			HOP_LIMIT : 8,
			NEXT_HEADER : 8,
			PAYLOAD_LEN : 16;
	char		S_EID[16],
			D_EID[16];
	__u32		DEST_PORT : 16,
			SOURCE_PORT : 16,
			UDP_CHECKSUM : 16,
			UDP_LENGTH : 16;
};

struct lisp_header4 {
        __u32           RESERVED : 28,
                        TYPE : 4,
	     	        TOTAL_LEN : 16,
                        TYPE_OF_SERVICE : 8,
                        IHL : 4,
                        VERSION : 4,
                        FRAGMENT_OFFSET : 13,
                        IPFLAGS : 3,
                        IDENTIFICATION : 16,
                        CHECKSUM : 16,
                        PROTOCOL : 8,
                        TTL : 8;
        char            S_EID[4],
                        D_EID[4];
        __u32           DEST_PORT : 16,
                        SOURCE_PORT : 16,
                        UDP_CHECKSUM : 16,
                        UDP_LENGTH : 16;
};

void *ipv4_encap_map_request(unsigned int * packetsize, void *buf, int size, void *saddr, void *daddr);
void *ipv6_encap_map_request(unsigned int * packetsize, void *buf, int size, void *saddr, void *daddr);
