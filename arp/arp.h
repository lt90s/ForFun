#ifndef _ARP_H_
#define _ARP_H_
#include <stdint.h>
#include <arpa/inet.h>
struct arphdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t req_mac[6];
    in_addr_t req_ip;
    uint8_t rep_mac[6];
    in_addr_t rep_ip;
} __attribute__((packed));

#define OP_REQUEST 1
#define OP_REPLY 2

const char *get_next_hop_mac(const char *interface, const char *ip);

#endif
