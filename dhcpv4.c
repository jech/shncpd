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
#include <string.h>
#include <time.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#include "shncpd.h"
#include "trickle.h"
#include "state.h"
#include "prefix.h"
#include "util.h"

/* Yes, this is an unusual combination. */

#define RENEW_TIME 240
#define REBIND_TIME 300
#define LEASE_TIME 1800

int dhcpv4_socket = -1;

static const unsigned char cookie[4] = {99, 130, 83, 99};
static const unsigned char zeroes[4] = {0, 0, 0, 0};

struct lease {
    unsigned char ip[4];
    int ifindex;
    unsigned char chaddr[16];
    unsigned char *cid;
    int cidlen;
    time_t end;
};

static struct lease *leases;
static int numleases = 0;
static int maxleases = 0;

void
flush_lease(struct lease *lease)
{
    int i = lease - leases;

    assert(i >= 0 && i < numleases);

    if(i < numleases - 1)
        leases[i] = leases[numleases - 1];
    MEM_UNDEFINED(leases + numleases - 1, sizeof(struct lease));
    numleases--;
}

struct lease *
find_lease(const unsigned char *ip, int create)
{
    int i;
    for(i = 0; i < numleases; i++)
        if(memcmp(leases[i].ip, ip, 4) == 0)
            return &leases[i];

    if(create) {
        if(numleases >= maxleases) {
            struct lease *nl =
                realloc(leases, (numleases * 2 + 2) * sizeof(struct lease));
            if(nl) {
                leases = nl;
                maxleases = numleases * 2 + 2;
            }
        }
        memset(&leases[numleases], 0, sizeof(struct lease));
        memcpy(leases[numleases].ip, ip, 4);
        return &leases[numleases++];
    }

    return NULL;
}

static int
lease_expired(const struct lease *lease)
{
    return lease->end < now.tv_sec;
}

static int
lease_match(const unsigned char *cid, int cidlen,
            const unsigned char *chaddr, const struct lease *lease)
{
    if(cidlen > 0 || lease->cidlen > 0)
        return lease->cidlen == cidlen && memcmp(lease->cid, cid, cidlen) == 0;
    else
        return memcmp(chaddr, lease->chaddr, 16) == 0;
}

static struct lease *
find_matching_lease(const unsigned char *cid, int cidlen,
                    const unsigned char *chaddr, struct prefix_list *pl)
{
    int i;

    for(i = 0; i < numleases; i++) {
        if(lease_match(cid, cidlen, chaddr, &leases[i]) &&
           (pl == NULL || prefix_list_within_v4(leases[i].ip, pl)))
            return &leases[i];
    }

    return NULL;
}

int
interface_dhcpv4_prio(struct interface *interface)
{
    if(serve_dhcpv4 && is_a_router())
        return 4;
    else
        return 0;
}

int
interface_dhcpv4(struct interface *interface)
{
    int i, prio;

    prio = interface_dhcpv4_prio(interface);
    if(prio == 0)
        return 0;

    for(i = 0; i < numneighs; i++) {
        if(neighs[i].interface == interface) {
            struct node *node = find_node(neighs[i].id, 0);
            unsigned char capa[2];
            capa[0] = 0;
            capa[1] = interface_dhcpv4_prio(interface) & 0x0F;
            if(node == NULL)
                continue;
            if((node->capabilities[1] & 0x0F) > prio)
                return 0;
            if(memcmp(node->capabilities, capa, 2) > 0)
                return 0;
            if(memcmp(node->id, myid, 4) > 0)
                return 0;
        }
    }
    return 1;
}

int
setup_dhcpv4_socket()
{
    int s, rc, one = 1;
    struct sockaddr_in sin;

    if(dhcpv4_socket >= 0) {
        close(dhcpv4_socket);
        dhcpv4_socket = -1;
    }

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    rc = setsockopt(s, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
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

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(67);

    rc = bind(s, (struct sockaddr*)&sin, sizeof(sin));
    if(rc < 0)
        goto fail;

    dhcpv4_socket = s;
    return s;

fail:
    return -1;
}

int
dhcpv4_setup()
{
    return setup_dhcpv4_socket();
}

void
dhcpv4_cleanup()
{
    if(dhcpv4_socket >= 0) {
        close(dhcpv4_socket);
        dhcpv4_socket = -1;
    }
}

static int
dhcpv4_parse(unsigned char *buf, int buflen,
             int *type_return, int *broadcast_return,
             unsigned char *xid_return, unsigned char *chaddr_return,
             unsigned char *ip_return, unsigned char *sid_return,
             unsigned char **cid_return, int *cidlen_return,
             unsigned char **uc_return, int *uclen_return)
{
    int i = 0;
    unsigned char xid[4] = {0}, chaddr[16] = {0}, ip[4] = {0}, sid[4] = {0};
    unsigned char *cid = NULL, *uc = NULL;
    int dhcp_type = -1, broadcast = 0, cidlen = 0, uclen = 0;

    if(buflen < 236)
        goto fail;

    if(buf[0] != 1 || buf[1] != 1 || buf[2] != 6)
        goto fail;
    i += 4;

    memcpy(xid, buf + i, 4);
    i += 4;

    /* secs */
    i += 2;

    /* flags */
    broadcast = (buf[i] & 0x80) != 0;
    i += 2;

    /* ciaddr */
    i += 4;

    /* yiaddr */
    i += 4;

    /* siaddr */
    i += 4;

    /* giaddr */
    if(buflen - i < 4)
        goto fail;
    if(memcmp(buf + i, zeroes, 4) != 0)
        goto fail;
    i += 4;

    /* chaddr */
    memcpy(chaddr, buf + i, 16);
    i += 16;

    /* sname */
    i += 64;

    /* file */
    i += 128;

    if(buflen - i < 4)
        goto fail;

    if(memcmp(buf + i, cookie, 4) != 0)
        goto fail;
    i += 4;

    while(i < buflen) {
        unsigned const char *tlv = buf + i;
        int type, bodylen;

        if(buflen - i < 1) {
            fprintf(stderr, "Received truncated DHCPv4 TLV.\n");
            goto fail;
        }

        type = tlv[0];
        if(type == 0) {
            i++;
            continue;
        }

        if(type == 255) {
            i++;
            goto done;
        }

        if(buflen - i < 2) {
            fprintf(stderr, "Received truncated DHCPv4 TLV.\n");
            goto fail;
        }

        bodylen = tlv[1];
        if(buflen - i < 2 + bodylen) {
            fprintf(stderr, "Received truncated DHCPv4 TLV.\n");
            goto fail;
        }

        switch(type) {
        case 50:
            if(bodylen != 4)
                goto fail;
            memcpy(ip, tlv + 2, 4);
            break;
        case 53:
            if(bodylen != 1)
                goto fail;
            dhcp_type = tlv[2];
            break;
        case 54:
            if(bodylen != 4)
                goto fail;
            memcpy(sid, tlv + 2, 4);
            break;
        case 61:
            if(cid != NULL)
                goto fail;
            cid = malloc(bodylen);
            if(cid == NULL)
                goto fail;
            memcpy(cid, tlv + 2, bodylen);
            cidlen = bodylen;
            break;
        case 77:
            if(uc != NULL)
                goto fail;
            uc = malloc(bodylen);
            if(uc == NULL)
                goto fail;
            memcpy(uc, tlv + 2, bodylen);
            uclen = bodylen;
            break;
        }
        i += 2 + bodylen;
    }
    /* Fall through */
 fail:
    fprintf(stderr, "Failed to parse DHCPv4 packet.\n");
    free(cid);
    free(uc);
    return -1;

 done:
    if(type_return)
        *type_return = dhcp_type;
    if(broadcast_return)
        *broadcast_return = broadcast;
    if(chaddr_return)
        memcpy(chaddr_return, chaddr, 16);
    if(xid_return)
        memcpy(xid_return, xid, 4);
    if(ip_return)
        memcpy(ip_return, ip, 4);
    if(sid_return)
        memcpy(sid_return, sid, 4);
    if(cid_return)
        *cid_return = cid;
    else
        free(cid);
    if(cidlen_return)
        *cidlen_return = cidlen;
    if(uc_return)
        *uc_return = uc;
    else
        free(uc);
    if(uclen_return)
        *uclen_return = uclen;
    return 1;
}

#define CHECK(_n) if(buflen < i + (_n)) goto fail
#define BYTE(_v) buf[i] = (_v); i++
#define BYTES(_v, _len) memcpy(buf + i, (_v), (_len)); i += (_len)
#define ZEROS(_len) memset(buf + i, 0, (_len)); i += (_len)
#define SHORT(_v) DO_HTONS(buf + i, (_v)); i += 2
#define LONG(_v) DO_HTONL(buf + i, (_v)); i += 4

static int
dhcpv4_send(int s, struct sockaddr_in *to, int type, const unsigned char *xid,
            const unsigned char *chaddr, const unsigned char *myaddr,
            const unsigned char *ip, int ifindex,
            const unsigned char *netmask, struct prefix_list *dns,
            int lease_time)
{
    int buflen = 1024;
    unsigned char buf[buflen];
    int i = 0;
    int rc;
    struct ifreq ifr;

    debugf("-> DHCPv4 (type %d) on interface %d\n", type, ifindex);

    MEM_UNDEFINED(buf, buflen);

    CHECK(236);
    BYTE(2);
    BYTE(1);
    BYTE(6);
    BYTE(0);
    BYTES(xid, 4);
    SHORT(0);
    SHORT(0);

    ZEROS(4);                   /* ciaddr */
    if(ip && lease_time >= 20) {
        BYTES(ip, 4);           /* yiaddr */
    } else {
        ZEROS(4);
    }
    BYTES(myaddr, 4);           /* siaddr */
    ZEROS(4);                   /* giaddr */
    BYTES(chaddr, 16);          /* chaddr */
    ZEROS(64);                  /* sname */
    ZEROS(128);                 /* file */

    CHECK(4);
    BYTES(cookie, 4);

    CHECK(3);
    BYTE(53);                   /* DHCP Message Type */
    BYTE(1);
    BYTE(type);

    CHECK(6);
    BYTE(54);                   /* Server Identifier */
    BYTE(4);
    BYTES(myaddr, 4);

    if(lease_time >= 20) {
        CHECK(6);
        BYTE(51);               /* IP Address Lease Time */
        BYTE(4);
        LONG(lease_time);

        CHECK(6);
        BYTE(58);               /* T1 */
        BYTE(4);
        LONG(min(RENEW_TIME, lease_time - 10));

        CHECK(6);
        BYTE(59);               /* T2 */
        BYTE(4);
        LONG(min(REBIND_TIME, lease_time - 15));
    }

    if(netmask) {
        CHECK(6);
        BYTE(1);
        BYTE(4);
        BYTES(netmask, 4);
    }

    CHECK(6);
    BYTE(3);
    BYTE(4);
    BYTES(myaddr, 4);

    if(dns && dns->numprefixes > 0) {
        int j;
        CHECK(2 + 4 * dns->numprefixes);
        BYTE(6);
        BYTE(4 * dns->numprefixes);
        for(j = 0; j < dns->numprefixes; j++) {
            BYTES((char*)&dns->prefixes[j].p + 12, 4);
        }
    }

    CHECK(1);
    BYTE(255);

    memset(&ifr, 0, sizeof(ifr));
    if_indextoname(ifindex, ifr.ifr_name);
    rc = setsockopt(dhcpv4_socket, SOL_SOCKET, SO_BINDTODEVICE,
                    &ifr, sizeof(ifr));
    if(rc < 0)
        return -1;

    rc = sendto(dhcpv4_socket, buf, i, MSG_DONTROUTE,
                (struct sockaddr*)to, sizeof(*to));

    setsockopt(dhcpv4_socket, SOL_SOCKET, SO_BINDTODEVICE, NULL, 0);
    return rc;

 fail:
    return -1;
}

static int
compute_netmask(unsigned char *mask,
                const unsigned char *ip, const struct prefix_list *pl)
{
    int i;
    unsigned int m;

    if(pl == NULL)
        return -1;

    for(i = 0; i < pl->numprefixes; i++) {
        if(prefix_within_v4(ip, &pl->prefixes[i])) {
            int plen;
            assert(pl->prefixes[i].plen >= 96);
            plen = pl->prefixes[i].plen - 96;
            m = 0xFFFFFFFFu << (32 - plen);
            DO_HTONL(mask, m);
            return plen;
        }
    }
    return -1;
}

static int
generate_v4(unsigned char *ip_return, unsigned char *mask_return,
            const struct prefix_list *pl)
{
    int i, j, rc;

    for(i = 0; i < 2; i++) {
        for(j = 0; j < 20; j++) {
            unsigned char ip[4];
            struct lease *lease;
            rc = generate_random_v4(ip, pl);
            if(rc < 0)
                return -1;
            lease = find_lease(ip, 0);
            if(!lease || (i > 0 && lease->end < now.tv_sec)) {
                int plen;
                unsigned char mask[4];
                unsigned int addr;
                plen = compute_netmask(mask, ip, pl);
                if(plen < 0 || plen > 30)
                    continue;
                /* Check that we are not in the first quarter. */
                DO_NTOHL(addr, ip);
                if((addr & (3 << (30 - plen))) == 0)
                    continue;
                memcpy(ip_return, ip, 4);
                memcpy(mask_return, mask, 4);
                return 1;
            }
        }
    }
    return -1;
}

static int
user_class_match(const unsigned char *uc, int uclen, const char *s)
{
    int slen = strlen(s);
    int i;

    i = 0;
    while(i + slen + 1 < uclen) {
        int clen = uc[i];
        if(clen == slen && memcmp(uc + i + 1, s, slen) == 0)
            return 1;
        i += clen + 1;
    }
    return 0;
}

int
dhcpv4_receive()
{
    int i, rc, buflen;
    const char broadcast_addr[4] = {255, 255, 255, 255};
    struct sockaddr_in from, to;
    int bufsiz = 1500;
    unsigned char buf[bufsiz];
    int type = -1, broadcast;
    unsigned char xid[4], chaddr[16], ip[4], sid[4], myaddr[4];
    unsigned char *cid = NULL, *uc = NULL;
    int cidlen = 0, uclen;
    struct interface *interface;
    struct prefix_list *pl = NULL, *dns = NULL;
    int ifindex = -1;
    unsigned char netmask[4];
    struct iovec iov[1];
    struct msghdr msg;
    int cmsglen = 100;
    char cmsgbuf[cmsglen];
    struct cmsghdr *cmsg = (struct cmsghdr*)cmsgbuf;

    iov[0].iov_base = buf;
    iov[0].iov_len = bufsiz;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg;
    msg.msg_controllen = cmsglen;

    rc = recvmsg(dhcpv4_socket, &msg, 0);

    if(rc < 0)
        return -1;

    if(from.sin_family != AF_INET || msg.msg_namelen < sizeof(from))
        return -1;

    buflen = rc;

    cmsg = CMSG_FIRSTHDR(&msg);
    while(cmsg != NULL) {
        if ((cmsg->cmsg_level == IPPROTO_IP) &&
            (cmsg->cmsg_type == IP_PKTINFO)) {
            struct in_pktinfo *info = CMSG_DATA(cmsg);
            ifindex = info->ipi_ifindex;
            break;
        }
        cmsg = CMSG_NXTHDR(&msg, cmsg);
    }

    interface = ifindex > 0 ? find_interface(ifindex) : NULL;

    if(interface == NULL)
        return -1;

    rc = interface_v4(interface, myaddr);
    if(rc <= 0) {
        return -1;
    }

    for(i = 0; i < interface->numassigned; i++) {
        struct assigned_prefix *ap = &interface->assigned[i];
        struct prefix_list *ppl;

        if(!ap->applied || !prefix_v4(&ap->assigned))
            continue;

        ppl = prefix_list_cons_prefix(pl, &ap->assigned);
        if(ppl != NULL)
            pl = ppl;
    }

    rc = dhcpv4_parse(buf, buflen, &type, &broadcast, xid, chaddr, ip,
                      sid, &cid, &cidlen, &uc, &uclen);
    if(rc < 0)
        return -1;

    debugf("   DHCPv4 (type %d) on %s", type, interface->ifname);

    if(user_class_match(uc, uclen, "HOMENET") ||
       (memcmp(sid, zeroes, 4) != 0 && memcmp(sid, myaddr, 4) != 0)) {
        debugf(" (ignored)\n");
        goto done;
    }

    debugf("\n");

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    if(broadcast || memcmp(&from.sin_addr, zeroes, 4) == 0)
        memcpy(&to.sin_addr, broadcast_addr, 4);
    else
        memcpy(&to.sin_addr, &from.sin_addr, 4);
    to.sin_port = htons(68);

    if(!interface_dhcpv4(interface))
        goto nak;

    dns = all_dhcp_data(0, 1, 0);

    switch(type) {
    case 1:                     /* DHCPDISCOVER */
    case 3: {                   /* DHCPREQUEST */
        struct lease *lease = NULL;
        int have_ip = memcmp(ip, zeroes, 4) != 0;

        if(type != 3 || !have_ip) {
            lease = find_matching_lease(cid, cidlen, chaddr, pl);
            if(!prefix_list_within_v4(ip, pl))
                lease = NULL;
        }

        if(lease == NULL && have_ip) {
            if(prefix_list_within_v4(ip, pl)) {
                lease = find_lease(ip, 0);
                if(lease && !lease_expired(lease) &&
                   !lease_match(cid, cidlen, chaddr, lease)) {
                    lease = NULL;
                }
            } else {
                lease = NULL;
            }
        }

        if(lease == NULL) {
            if(type == 3)
                goto nak;
            rc = generate_v4(ip, netmask, pl);
            if(rc < 0)
                goto nak;
            lease = find_lease(ip, 1);
        } else {
            rc = compute_netmask(netmask, lease->ip, pl);
            if(rc < 0)
                goto nak;
        }

        if(lease == NULL)
            goto nak;

        memcpy(lease->chaddr, chaddr, 16);
        lease->ifindex = ifindex;
        lease->end = type == 1 ? now.tv_sec : now.tv_sec + LEASE_TIME + 10;
        free(lease->cid);
        lease->cidlen = cidlen;
        lease->cid = cid;
        cid = NULL;

        rc = dhcpv4_send(dhcpv4_socket, &to,
                         type == 1 ? 2 : 5, xid, chaddr, myaddr,
                         lease->ip, ifindex, netmask, dns, LEASE_TIME);
        if(rc < 0)
            perror("dhcpv4_send");
        break;
    }
    case 4: {                   /* DHCPDECLINE */
        struct lease *lease = find_lease(ip, 0);
        fprintf(stderr, "Received DHCPDECLINE");
        if(lease && lease->end >= now.tv_sec) {
            fprintf(stderr, " (already assigned).\n");
        } else if(lease && lease->end >= now.tv_sec - LEASE_TIME) {
            fprintf(stderr, " (marking as used).\n");
            free(lease->cid);
            lease->cid = NULL;
            lease->cidlen = 0;
            cid = NULL;
            memset(lease->chaddr, 0, 16);
            lease->end = now.tv_sec + LEASE_TIME;
        } else {
            fprintf(stderr, " (ignored).\n");
        }
        break;
    }
    case 7: {                   /* DHCPRELEASE */
        struct lease *lease = find_matching_lease(cid, cidlen, chaddr, NULL);
        if(lease)
            lease->end = now.tv_sec;
        break;
    }
    case 8: {                   /* DHCPINFORM */
        rc = dhcpv4_send(dhcpv4_socket, &to,
                         5, xid, chaddr, myaddr,
                         NULL, ifindex, NULL, dns, 0);
        if(rc < 0)
            perror("dhcpv4_send");
        break;
    }
    }

    goto done;

 nak:
    if(type == 3)
        dhcpv4_send(dhcpv4_socket, &to, 6, xid, chaddr, myaddr, ip, ifindex,
                    NULL, NULL, 0);
 done:
    free(cid);
    free(uc);
    destroy_prefix_list(dns);
    destroy_prefix_list(pl);
    return 1;
}
