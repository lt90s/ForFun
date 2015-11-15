#include "self_include/l_net.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include<netpacket/packet.h>
void hexdump(u_int8_t *obj, size_t sz)
{
        int i;
        for (i = 0; i < sz; i++) {
                printf("%02x\t", obj[i]);
                if ((i + 1) % 4 == 0) {
                        printf("\n");
                }
        }
        printf("\n");
}

void handle_IP(const struct iphdr *ip, int n)
{
        static int cnt = 0;
        struct in_addr s, d;
        s.s_addr = ip->saddr;
        d.s_addr = ip->daddr;
        printf("Packet Number %d\n", ++cnt);
        printf("IP VERSION: %d\n", ip->version);
        printf("IP Header Length: %d\n", ip->ihl);
        printf("IP Total Length: %d\n", ntohs(ip->tot_len));
        printf("IP Source Addr: %s\n", inet_ntoa(s));
        printf("IP Destination Addr: %s\n", inet_ntoa(d));
        printf("IP Protocol: %d\n", ip->protocol);
}
void show_mac(const uint8_t *mac)
{
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2],
                                                                               mac[3], mac[4], mac[5]);
}

void handle_MAC(const struct ethhdr *eth)
{
        printf("DST MAC: ");
        show_mac(eth->h_dest);
        printf("SRC MAC: ");
        show_mac(eth->h_source);
        printf("PROTOCOL: %x\n", ntohs(eth->h_proto));
}
void swap_MAC(uint8_t *ma, uint8_t *mb)
{
        uint8_t tmp[ETH_ALEN];
        memcpy(tmp, ma, ETH_ALEN);
        memcpy(ma, mb, ETH_ALEN);
        memcpy(mb, tmp, ETH_ALEN);
}

int main(int argc, char *argv)
{
        int raw_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        char buf[BUFSIZ];
        struct ifreq ifr;
        bzero(&ifr, sizeof(ifr));
        struct sockaddr_in *sin = NULL;
        strcpy(ifr.ifr_name, "eth0");
        if (ioctl(raw_sock, SIOCGIFADDR, &ifr) < 0) {
                perror("ioctl");
        } else {
                sin = (struct sockaddr_in *)&ifr.ifr_addr;
                printf("IP: %s\n", inet_ntoa(sin->sin_addr));
        }
        int on = 1;
        if (setsockopt(raw_sock, SOL_SOCKET, SO_BROADCAST,
                                                                        &on, sizeof(on)) < 0) {
                printf("setsockopt SO_BROADCAST failed\n");
                return -1;
        }
        for (;;) {
                int n = recvfrom(raw_sock, buf, BUFSIZ, 0, NULL, NULL);
                if (n < 0) {
                        switch (errno) {
                        case EAGAIN:
                        case EINTR:
                                continue;
                        default:
                                perror("Read Error");
                                return -1;
                        }
                } else if (n == 0) {
                        printf("Read returns 0\n");
                        break;
                } else {
                        struct ethhdr *eth = (struct ethhdr *)buf;
                        struct iphdr *ip = (struct iphdr *)(eth + 1);
                        if (ip->protocol != 1)
                                continue;

                        printf("RECV: \n");
                        handle_MAC(eth);
                        handle_IP(ip, n);
                        swap_MAC(eth->h_dest, eth->h_source);
                        struct in_addr inaddr;
                        inet_aton("192.168.255.129", &inaddr);
                        ip->saddr = ip->daddr;
                        ip->daddr = inaddr.s_addr;
                        printf("SEND: \n");
                        handle_MAC(eth);
                        handle_IP(ip, n);
                        struct sockaddr_ll sa;
                        bzero(&sa, sizeof(sa));
                        //sa.sll_family = AF_PACKET;
                        sa.sll_ifindex = getif_idx("eth0");
                        if (sa.sll_ifindex < 0) {
                                printf("getif_idx error\n");
                                return -1;
                        }
                        //sa.sll_protocol = htons(ETH_P_ALL);
                        n = sendto(raw_sock, buf, n, 0, (struct sockaddr *)&sa,
                                                                               sizeof(sa));
                        if (n < 0) {
                                perror("sendto failed");
                        } else {
                                printf("send %d bytes\n", n);
                        }
                }
        }
        return 0;
}
int test_inet_addr(int argc, char *argv[])
{
        if (argc != 2) {
                printf("%s IP\n", argv[0]);
                return -1;
        }

        in_addr_t ip = inet_addr(argv[1]);
        if (ip == INADDR_NONE) {
                printf("Invalid IP: %s\n", argv[1]);
                return -1;
        } else {
                printf("Numeric IP: %#x\n", ntohl(ip));
        }
        return 0;
}
