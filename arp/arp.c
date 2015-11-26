#include "arp.h"
#include "l_net.h"
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>


static void arphdr_init(const char *interface, const char *ip, struct arphdr *arp)
{
        arp->htype = htons(1);
        arp->ptype = htons(ETH_P_IP);
        arp->hlen = 6;
        arp->plen = 4;
        arp->opcode = htons(OP_REQUEST);
        memcpy(arp->req_mac, getif_hwaddr(interface), 6);
        bzero(arp->rep_mac, sizeof(arp->rep_mac));
        arp->req_ip = getif_ip(interface);
        arp->rep_ip = inet_addr(ip);
}

/*
 * @interface: eth0 or eth1 ...
 * @ip: target ip address
 */
const char *get_next_hop_mac(const char *interface, const char *ip)
{
        static char mac[6];
        uint8_t arp_packet[128];
        uint8_t buf[128];
        int arp_size = sizeof(struct ethhdr) + sizeof(struct arphdr);
        struct ethhdr *eth = (struct ethhdr *)arp_packet;
        struct arphdr *arp = (struct arphdr *)(eth + 1);
        bzero(arp_packet, sizeof(arp_packet));
        arphdr_init(interface, ip, arp);
        memcpy(eth->h_source, arp->req_mac, 6);
        memset(eth->h_dest, 0xff, 6);
        eth->h_proto = htons(ETH_P_ARP);
        arp_size = 60;
        int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) {
                return NULL;
        }
        struct sockaddr_ll sll;
        bzero(&sll, sizeof(sll));
        if ((sll.sll_ifindex = getif_idx(interface)) < 0) {
                close(sock);
                return NULL;
        }
        int i;
        /* send 4 arp requests */
        for (i = 0; i < 4; i++) {
                if (sendto(sock, arp_packet, arp_size, 0, (struct sockaddr *)&sll, sizeof(sll)) != arp_size) {
                        close(sock);
                        return NULL;
                }
        }
        /* 
         * can't get the arp reply out of 1000 packets?
         * well, 1000 works for me
         */
        for (i = 0; i < 1000; i++) {
                int n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
                if (n < 0) {
                        close(sock);
                        return NULL;
                }
                struct ethhdr *r_eth = (struct ethhdr *)buf;
                struct arphdr *r_arp = (struct arphdr *)(r_eth + 1);
                if (r_eth->h_proto == htons(ETH_P_ARP)) {
                        if ( r_arp->opcode == htons(OP_REPLY)
                                && r_arp->req_ip == arp->rep_ip && r_arp->rep_ip == arp->req_ip) {
                                memcpy(mac, r_eth->h_source, 6);
                                close(sock);
                                return mac;
                        }
                }
        }
        close(sock);
        return NULL;
}
