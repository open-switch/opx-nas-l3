/*
 * Copyright (c) 2016 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*
 * nas_nl_route_scale.cpp
 *
 */

#include "std_mac_utils.h"
#include "std_ip_utils.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <iostream>

#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <gtest/gtest.h>

struct nl_socket {
    int fd;
    struct sockaddr_nl addr;
};

static inline void* nlmsg_tail(struct nlmsghdr * m) {
    return (void *) (((char*)m) + NLMSG_ALIGN(m->nlmsg_len));
}

void * nlmsg_reserve(struct nlmsghdr * m, int maxlen, int len) {
    void * p = nlmsg_tail(m);
    if ((int)(NLMSG_ALIGN(m->nlmsg_len) + RTA_ALIGN(len)) > maxlen) {
        return NULL;
    }
    m->nlmsg_len = NLMSG_ALIGN(m->nlmsg_len) + RTA_ALIGN(len);
    return p;
}

int nl_socket_close(struct nl_socket *nl)
{
    int ret = close(nl->fd);
    free(nl);
    return ret;
}

struct nl_socket *nl_socket_open(int bus)
{
    struct nl_socket *nl;

    nl = (struct nl_socket *) calloc(sizeof(struct nl_socket), 1);
    if (nl == NULL)
        return NULL;

    nl->fd = socket(AF_NETLINK, SOCK_RAW, bus);
    if (nl->fd == -1) {
        free(nl);
        return NULL;
    }

    return nl;
}
int nl_socket_bind(struct nl_socket *nl, unsigned int groups, pid_t pid)
{
    int ret;
    socklen_t addr_len;

    nl->addr.nl_family = AF_NETLINK;
    nl->addr.nl_groups = groups;
    nl->addr.nl_pid = pid;

    ret = bind(nl->fd, (struct sockaddr *) &nl->addr, sizeof (nl->addr));
    if (ret < 0)
        return ret;

    addr_len = sizeof(nl->addr);
    ret = getsockname(nl->fd, (struct sockaddr *) &nl->addr, &addr_len);
    if (ret < 0)
        return ret;

    if (addr_len != sizeof(nl->addr)) {
        errno = EINVAL;
        return -1;
    }
    if (nl->addr.nl_family != AF_NETLINK) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

ssize_t nl_socket_sendto(const struct nl_socket *nl, const void *buf, size_t len)
{
    static const struct sockaddr_nl snl = {
            .nl_family = AF_NETLINK
    };
    return sendto(nl->fd, buf, len, 0,
                 (struct sockaddr *) &snl, sizeof(snl));
}


int nlmsg_add_attr(struct nlmsghdr * m, int maxlen, int type, const void * data, int attr_len) {
    struct rtattr *rta = (struct rtattr *)nlmsg_reserve(m,maxlen,RTA_LENGTH(attr_len));

    if (rta==NULL) return -1;

    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(attr_len);
    memcpy(RTA_DATA(rta), data, attr_len);
    return m->nlmsg_len;
}

char *buf = NULL;

int nl_route (int is_add_route, int argc, char *argv[])
{
    int iface;
    iface = if_nametoindex(argv[1]);
    if (iface == 0) {
            printf("Bad interface name\n");
            exit(EXIT_FAILURE);
    }

    in_addr_t dst;
    if (!inet_pton(AF_INET, argv[2], &dst)) {
            printf("Bad destination\n");
            exit(EXIT_FAILURE);
    }

    uint32_t mask;
    if (sscanf(argv[3], "%u", &mask) == 0) {
            printf("Bad CIDR\n");
            exit(EXIT_FAILURE);
    }

    in_addr_t gw;
    if (argc >= 5 && !inet_pton(AF_INET, argv[4], &gw)) {
            printf("Bad gateway\n");
            exit(EXIT_FAILURE);
    }

    int32_t count = 1;
    if ( argc >=6 && sscanf(argv[5], "%d", &count) == 0) {
            printf("Bad count\n");
            exit(EXIT_FAILURE);
    }

    int32_t bulk_count = 1;
    if ( argc >=7 && sscanf(argv[6], "%d", &bulk_count) == 0) {
        printf("Bad bulk count\n");
        exit(EXIT_FAILURE);
    }
    if ( count < bulk_count) {
        printf("\r\nbulk count cannot be more than actual count\n");
        exit(EXIT_FAILURE);
    }
//  printf ("mask %u count %d bulk_count %d\r\n", mask, count, bulk_count);

    struct nl_socket *nl;

    nl = nl_socket_open(NETLINK_ROUTE);
    if (nl == NULL) {
        perror("nl_socket_open");
        exit(EXIT_FAILURE);
    }

    if (nl_socket_bind(nl, 0, 0) < 0) {
        perror("nl_socket_bind");
        exit(EXIT_FAILURE);
    }

    int bulk_buf_size = 0;
    bulk_buf_size = 1000+((sizeof(struct nlmsghdr)+sizeof(struct rtmsg)+200) * bulk_count);
    buf = (char *) malloc (bulk_buf_size);
    if (buf == NULL) {
        perror ("malloc error");
        exit(EXIT_FAILURE);
   }

    struct nlmsghdr *nlh = NULL;
    struct rtmsg *rtm = NULL;

    uint32_t addr_len = 4;
    int i;

    int filled_buf_size = 0;
    do {
        memset (buf, 0, bulk_buf_size);
        filled_buf_size = 0;

        for (i = 0; (i < bulk_count) && count; i++, count--)
        {
            nlh = (struct nlmsghdr *)
                    nlmsg_reserve((struct nlmsghdr *) (buf + filled_buf_size),
                                  (bulk_buf_size - filled_buf_size), sizeof(struct nlmsghdr));

            nlh->nlmsg_flags = NLM_F_REQUEST;

            if (is_add_route == 1) {
                nlh->nlmsg_type = RTM_NEWROUTE;
                nlh->nlmsg_flags |= NLM_F_CREATE;
            } else {
                nlh->nlmsg_type = RTM_DELROUTE;
            }
            nlh->nlmsg_seq = time(NULL);
            nlh->nlmsg_pid = 0;


            rtm = (struct rtmsg *) nlmsg_reserve (nlh,bulk_buf_size,sizeof(struct rtmsg));

            rtm->rtm_family = AF_INET;
            rtm->rtm_dst_len = mask;
            rtm->rtm_src_len = 0;
            rtm->rtm_tos = 0;
            rtm->rtm_protocol = RTPROT_UNSPEC; //RTPROT_ZEBRA; //RTPROT_UNSPEC; //RTPROT_BOOT;
            rtm->rtm_table = RT_TABLE_MAIN;
            rtm->rtm_type = RTN_UNICAST;
            /* is there any gateway? */
            if (!is_add_route)
                rtm->rtm_scope = RT_SCOPE_NOWHERE;
            else
                rtm->rtm_scope = RT_SCOPE_UNIVERSE;
            rtm->rtm_flags = 0;

            nlmsg_add_attr(nlh,bulk_buf_size,RTA_DST,(char *) &dst,addr_len);
            dst = ntohl (dst);
            dst += 256;
            dst = htonl (dst);
            nlmsg_add_attr(nlh,bulk_buf_size,RTA_OIF,(char *) &iface,sizeof(iface));
            if (argc >= 5)
                nlmsg_add_attr(nlh,bulk_buf_size,RTA_GATEWAY,(char *) &gw,addr_len);

            filled_buf_size += nlh->nlmsg_len;
//          printf ("\rbulk iteration:(%d) nlh->nlmsg_len %d filled_buf_size %d rtm(%p)\r\n", i, nlh->nlmsg_len, filled_buf_size, rtm);
        }
//      printf ("\rsending in bulk: num entries bulked:%d, filled_buf_size:%d\r\n", i, filled_buf_size);
        if (nl_socket_sendto(nl, (struct nlmsghdr *) buf, filled_buf_size) < 0) {
            perror("nl_socket_send");
            free (buf);
            exit(EXIT_FAILURE);
        }
    } while (count);

    nl_socket_close(nl);
    free (buf);

    return 0;
}

int g_argc = 0;
char *g_argv[10];

TEST(std_nas_route_test, nl_add_route) {
   nl_route (1, g_argc, g_argv);
}

TEST(std_nas_route_test, nl_del_route) {
   nl_route (0, g_argc, g_argv);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    if (argc <= 3) {
        printf("Usage: %s --gtest_filter=*<test_func> iface destination cidr gateway [route_count] [bulk_count]\n", argv[0]);
        printf("Example: %s --gtest_filter=*nl_add_route eth0 10.0.1.12 32 10.0.1.11 1000 100\n", argv[0]);
        printf("Example: %s --gtest_filter=*nl_del_route eth0 10.0.1.12 32 10.0.1.11 1000 100\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    printf("Input: %s %s %s %s %s %s %s\n",
           argv[0], argv[1], argv[2], argv[3],
           ((argc >4)?argv[4]:""),
           ((argc >5)?argv[5]:""),
           ((argc >6)?argv[6]:""));

    g_argc = argc;
    int loop = argc;
    do {
        g_argv[loop] = argv[loop];
    } while (loop--);
    printf("___________________________________________\n");
    printf("___________________________________________\n");

    return RUN_ALL_TESTS();
}

