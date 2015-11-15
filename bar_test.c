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
        printf("\n\n");
}

int main(int argc, char *argv)
{
        int raw_sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
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
                        struct iphdr *ip = (struct iphdr *)buf;
                        if (ip->protocol != 1) {
                                continue;
                        }
                        handle_IP((struct iphdr *)buf, n);
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
