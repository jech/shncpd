/*
Copyright (c) 2015 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "prefix.h"
#include "trickle.h"
#include "state.h"
#include "shncpd.h"
#include "ra.h"
#include "util.h"
#include "kernel.h"

int ra_socket = -1;
int previously_a_router = 0;

int
setup_ra_socket()
{
    int s, i, rc, one = 1, two = 2, ff = 255;
    struct icmp6_filter filter;

    if(ra_socket >= 0) {
        close(ra_socket);
        ra_socket = -1;
    }

    s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if(s < 0)
        return -1;

    rc = setsockopt(s, IPPROTO_RAW, IPV6_CHECKSUM, &two, sizeof(two));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ff, sizeof(ff));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ff, sizeof(ff));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    for(i = 0; i < numinterfaces; i++) {
        struct ipv6_mreq mreq;
        const unsigned char all_routers[16] =
            {0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
        if(interfaces[i].ifindex <= 0)
            continue;
        memset(&mreq, 0, sizeof(mreq));
        memcpy(&mreq.ipv6mr_multiaddr, &all_routers, 16);
        mreq.ipv6mr_interface = interfaces[i].ifindex;
        rc = setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                        (char*)&mreq, sizeof(mreq));
        if(rc < 0)
            goto fail;
    }

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);

    rc = setsockopt(s, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFD, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFD, rc | FD_CLOEXEC);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFL, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFL, (rc | O_NONBLOCK));
    if(rc < 0)
        goto fail;

    ra_socket = s;
    return s;

fail:
    return -1;
}

#define CHECK(_n) if(buflen < i + (_n)) goto fail
#define BYTE(_v) buf[i] = (_v); i++
#define BYTES(_v, _len) memcpy(buf + i, (_v), (_len)); i += (_len)
#define SHORT(_v) DO_HTONS(buf + i, (_v)); i += 2
#define LONG(_v) DO_HTONL(buf + i, (_v)); i += 4

/* router is 1 for default router, and -1 for not a router at all. */

static int
send_ra(struct interface *interface, const struct sockaddr_in6 *to,
        int router)
{
    int buflen = 1024;
    unsigned char buf[buflen];
    int i = 0, j;

    CHECK(16);
    BYTE(134);
    BYTE(0);
    SHORT(0);
    BYTE(0);
    BYTE(0);
    SHORT(router > 0 ? 3600 : 0);
    LONG(0);
    LONG(0);

    if(interface) {
        if(interface->retractions) {
            for(j = 0; j < interface->retractions->numprefixes; j++) {
                struct prefix *p = &interfaces->retractions->prefixes[j];
                CHECK(32);
                BYTE(3);
                BYTE(4);
                BYTE(p->plen);
                BYTE(0x80);
                LONG(0);
                LONG(0);
                LONG(0);
                BYTES(&p->p, 16);
            }
        }

        destroy_prefix_list(interface->retractions);
        interface->retractions = NULL;

        for(j = 0; j < interface->numassigned; j++) {
            struct assigned_prefix *ap = &interface->assigned[j];
            struct prefix *p = &ap->assigned;

            if(!ap->applied || prefix_v4(&ap->assigned))
                continue;

            CHECK(32);
            BYTE(3);
            BYTE(4);
            BYTE(p->plen);
            BYTE(router < 0 ? 0x80 : (0x80 | 0x40));
            LONG(router < 0 ? 0 : 3600);
            LONG(router < 0 ? 0 : 1800);
            LONG(0);
            BYTES(&p->p, 16);
        }
    }

    debugf("-> Router Advertisement\n");

    return sendto(ra_socket, buf, i, 0, (struct sockaddr*)to, sizeof(*to));

 fail:
    return -1;
}

void
ra_retract(const struct prefix *prefix)
{
    int i;
    for(i = 0; i < numinterfaces; i++) {
        if(interfaces[i].ifindex > 0) {
            struct prefix_list *pl =
                prefix_list_cons_prefix(interfaces[i].retractions, prefix);
            if(pl)
                interfaces[i].retractions = pl;
        }
    }
}

void
schedule_ra(struct interface *interface, int soon, int override)
{
    int a, b;

    if(interface == NULL) {
        int i;
        for(i = 0; i < numinterfaces; i++) {
            if(interfaces[i].ifindex > 0)
                schedule_ra(&interfaces[i], soon, override);
        }
        return;
    }

    if(soon >= 2) {
        a = 0;
        b = MAX_RA_DELAY_TIME;
    } else if(soon == 1) {
        a = 0;
        b = 5000;
    } else {
        a = MIN_RTR_ADV_INTERVAL;
        b = MAX_RTR_ADV_INTERVAL;
    }

    if(!override && interface->ra_timeout.tv_sec > 0 &&
       ts_minus_msec(&interface->ra_timeout, &now) < b)
        return;

    ts_add_msec(&interface->ra_timeout, &now, a);
    ts_add_random(&interface->ra_timeout, &interface->ra_timeout, b - a);
}


static int
send_multicast_ra(struct interface *interface, int router)
{
    const unsigned char all_nodes[16] =
        {0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    struct sockaddr_in6 to;
    int rc;

    if(interface == NULL) {
        int i;
        for(i = 0; i < numinterfaces; i++) {
            if(interfaces[i].ifindex > 0)
                send_multicast_ra(&interfaces[i], router);
        }
        return 1;
    }

    if(ts_minus_msec(&now, &interface->last_ra_sent) < MIN_DELAY_BETWEEN_RAS)
        return 0;

    memset(&to, 0, sizeof(to));
    to.sin6_family = AF_INET6;
    memcpy(&to.sin6_addr, all_nodes, 16);
    to.sin6_scope_id = interface->ifindex;
    rc = send_ra(interface, &to, router);
    interface->last_ra_sent = now;
    return rc;
}

static int
recv_rs()
{
    int buflen = 1500, rc;
    unsigned char buf[buflen];
    struct sockaddr_in6 from;
    socklen_t fromlen = sizeof(from);
    struct interface *interface;

    rc = recvfrom(ra_socket, buf, buflen, 0, (struct sockaddr*)&from, &fromlen);
    if(rc < 0)
        return rc;

    if(fromlen < sizeof(struct sockaddr_in6) || from.sin6_family != AF_INET6)
        return 0;

    /* XXX verify hop limit. */

    if(rc < 8)
        return 0;

    if(buf[0] != 133 || buf[1] != 0)
        return 0;

    if(from.sin6_scope_id == 0)
        return 0;

    interface = find_interface(from.sin6_scope_id);
    if(interface == NULL)
        return 0;

    debugf("  Router Solicitation on %s\n", interface->ifname);
    schedule_ra(interface, 1, 0);

    return 1;
}

int
ra_setup()
{
    int rc;
    rc = setup_ra_socket();
    if(rc < 0) {
        perror("setup_ra_socket");
        return rc;
    }
    schedule_ra(NULL, 1, 2);
    return 1;
}

void
ra_cleanup()
{
    if(ra_socket >= 0) {
        if(previously_a_router) {
            debugf("Sending RA retractions.\n");
            send_multicast_ra(NULL, -1);
        }
        previously_a_router = 0;
        close(ra_socket);
    }
    ra_socket = -1;
}

int
router_advertisement(int doread)
{
    int i, rc;

    if(doread) {
        rc = recv_rs();
        if(rc > 0) {
        } else if(errno != EAGAIN) {
            perror("recv(RA)");
        }
    }

    for(i = 0; i < numinterfaces; i++) {
        struct interface *interface = &interfaces[i];
        if(interface->ifindex <= 0)
            continue;

        if(kernel_router() > 0) {
            if(!previously_a_router)
                debugf("Became a router -- sending RAs.\n");
            previously_a_router = 1;
            if(ts_compare(&now, &interface->ra_timeout) >= 0) {
                schedule_ra(interface, 0, 1);
                rc = send_multicast_ra(interface, 1);
                if(rc < 0)
                    perror("send_ra");
            }
        } else {
            schedule_ra(interface, 0, 1);
            if(previously_a_router) {
                debugf("No longer a router -- sending RA retractions.\n");
                send_multicast_ra(NULL, -1);
            }
            previously_a_router = 0;
        }
    }
    return 1;
}
