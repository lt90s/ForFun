#ifndef _L_NET_H_
#define _L_NET_H_
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/tcp.h>

static inline int
__getif_idx(int sock_fd, const char *interface)
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, interface);
	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr, sizeof(ifr)) < 0) {
		return -1;
	}
	return ifr.ifr_ifindex;
}

static inline int
getif_idx(const char *interface)
{
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    return __getif_idx(sock_fd, interface);
}

static inline in_addr_t
__getif_ip(int sock_fd, const char *interface)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;
    strcpy(ifr.ifr_name, interface);
    if (ioctl(sock_fd, SIOCGIFADDR, &ifr, sizeof(ifr)) < 0) {
		return -1;
	}
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	return sin->sin_addr.s_addr;
}

static inline in_addr_t
getif_ip(const char *interface)
{
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	return __getif_ip(sock_fd, interface);
}


static inline const u_int8_t *
__getif_hwaddr(int sock_fd, const char *interface)
{
	static u_int8_t hw[6];
	struct ifreq ifr;
	strcpy(ifr.ifr_name, interface);
	if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr, sizeof(ifr)) < 0) {
		return NULL;
	}
	memcpy(hw, ifr.ifr_hwaddr.sa_data, 6);
	return (const u_int8_t *)hw;
}

static inline const u_int8_t *
getif_hwaddr(const char *interface)
{
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	return __getif_hwaddr(sockfd, interface);
}


/*
 * Header Checksum
 */
static uint16_t iph_sum(uint16_t *ip, int size)
{
	uint32_t sum = 0;
	while (size > 1) {
		sum += *ip++;
		size -= sizeof(uint16_t);
	}
	if (size) {
		sum += *(uint8_t *)ip;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (uint16_t)~sum;
}

/* pseudo TCP header */
struct psd_tcphdr {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t proto;
	uint16_t length;
};

static uint16_t tcphdr_sum(struct psd_tcphdr *psd, uint16_t *s, int size)
{
	uint16_t sum_psd = ~iph_sum((uint16_t *)psd, sizeof(*psd));
	uint16_t sum_s = ~iph_sum(s, size);
	uint32_t sum = sum_psd + sum_s;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}
static void dump_IP(const struct iphdr *ip)
{
	struct in_addr s, d;
	if (ip == NULL) {
        return;
	}
    s.s_addr = ip->saddr;
	d.s_addr = ip->daddr;
	printf("IP VERSION: %d\n", ip->version);
	printf("IP Header Length: %d\n", ip->ihl);
	printf("IP Total Length: %d\n", ntohs(ip->tot_len));
	printf("IP Checksum: %#x\n", ntohs(ip->check));
	printf("IP Source Addr: %s\n", inet_ntoa(s));
	printf("IP Destination Addr: %s\n", inet_ntoa(d));
	printf("IP Protocol: %d\n", ip->protocol);
}

static void dump_TCP(const struct tcphdr *tcp)
{
	printf("TCP SOURCE PORT: %d\n", ntohs(tcp->source));
	printf("TCP DEST PORT: %d\n", ntohs(tcp->dest));
	printf("TCP CHECKSUM: %#x\n", ntohs(tcp->check));
	if (tcp->syn) {
		if (tcp->ack) {
			printf("TCP SYN & ACK PACKET\n");
		} else {
			printf("TCP SYN PACKET\n");
		}
	} else if (tcp->ack) {
		printf("TCP ACK PACKET\n");
	}
	printf("TCP HEADER LENGTH: %d\n", tcp->doff << 2);
}


/*  GRE Related */

struct grehdr {
	uint8_t flag;
	uint8_t ver;
	uint16_t protocol;
	union {
		struct {
			uint16_t csum;
			uint16_t offset;
			uint32_t key;
		} csum_key;
		uint32_t key;
	} u;
};

#define GRE_PROTO_IP 0x0800
#define GRE_KEY_BIT 5
#define GRE_CSUM_BIT 7
static inline int grehdr_has_checksum(const struct grehdr *gre)
{
	return (gre->flag & (1u << GRE_CSUM_BIT));
}

static inline int grehdr_has_key(const struct grehdr *gre)
{
	return (gre->flag & (1u << GRE_KEY_BIT));
}

static inline int grehdr_get_length(const struct grehdr *gre)
{
	return (8 + grehdr_has_checksum(gre) ? 4 : 0);
}

static void dump_gre(const struct grehdr *gre)
{
	uint32_t key;
	if (grehdr_has_checksum(gre)) {
		printf("gre checksum bit set\n");
		uint16_t sum = gre->u.csum_key.csum;//*(uint16_t *)(gre + 1);
		key = gre->u.csum_key.key;
		printf("checksum: %#x\n", ntohs(sum));
	} else {
		key = gre->u.key;
	}
	if (grehdr_has_key(gre)) {
		printf("gre key bit set\n");
		printf("key: %#x\n", ntohl(key));
	}
	printf("protocol; %#x\n", ntohs(gre->protocol));
}

#endif
