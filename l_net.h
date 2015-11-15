#ifndef _L_NET_H_
#define _L_NET_H_

#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

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
#endif
