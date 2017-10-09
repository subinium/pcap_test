#include <stdint.h>

#ifndef NET_STRUCT_H
#define NET_STRUCT_H

/* eth */
#define ETH_ALEN 6
#define ETH_HLEN 14


struct eth_hdr {
	uint8_t dst[ETH_ALEN];
	uint8_t src[ETH_ALEN];
	uint16_t type;
	uint8_t data[0];
} __attribute__((packed));

/* ipv4 */
#define IPV4_VER(XX) ((uint8_t)(((XX)->VIHL & 0xF0) >> 4))
#define IPV4_HL(XX)  ((uint8_t)(((XX)->VIHL & 0x0F) << 2))

#define IPV4_HL_MIN 20
#define IPV4_ALEN 0x04


struct ipv4_hdr {
	uint8_t VIHL;
	uint8_t DSCP_ECN;
	uint16_t length;
	uint16_t id;
	uint16_t FF;
	uint8_t TTL;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t src[4];
	uint8_t dst[4];
	uint8_t data[0];
} __attribute__((packed));

/* tcp */
#define TCP_HL(XX) ((uint8_t)((((uint8_t*)(&(XX)->DRF))[0] & 0xF0) >> 2))
#define TCP_PAYLOAD_MAXLEN 16

struct tcp_hdr {
	uint16_t src;
	uint16_t dst;
	uint32_t seq;
	uint32_t ack;
	uint16_t DRF; 
	uint16_t wsize;
	uint16_t checksum;
	uint16_t urg;
	uint8_t payload[0];
} __attribute__((packed));

#endif
