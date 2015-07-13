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
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include "shncpd.h"
#include "trickle.h"
#include "state.h"
#include "send.h"
#include "receive.h"
#include "prefix.h"
#include "util.h"

int
parse_packet(const unsigned char *buf, int buflen,
             struct sockaddr_in6 *from, int unicast,
             struct interface *interface)
{
    unsigned char id[4];
    unsigned int eid = 42;      /* silence gcc */
    int have_id = 0;
    int i = 0, rc;
    int recompute = 0;

    if(debug_level >= 3)
        debugf("Received %d bytes.\n", buflen);

    while(i < buflen) {
        unsigned const char *tlv = buf + i;
        int type, bodylen;

        if(buflen - i < 4) {
            fprintf(stderr, "Received truncated TLV.\n");
            goto fail;
        }

        DO_NTOHS(type, tlv);
        DO_NTOHS(bodylen, tlv + 2);
        if(buflen - i < 4 + bodylen) {
            fprintf(stderr, "Received truncated TLV.\n");
            goto fail;
        }

        switch(type) {
        case 1: {
            debugf("   REQ-NETWORK-STATE\n");
            int i;
            buffer_network_state(from, NULL);
            for(i = 0; i < numnodes; i++)
                buffer_node_state(&nodes[i], 0, from, NULL);
            break;
        }
        case 2: {
            struct node *node;
            if(bodylen < 4) {
                fprintf(stderr, "Truncated REQ-NODE-STATE\n");
                goto fail;
            }
            debugf("   REQ-NODE-STATE %s\n", format_32(tlv + 4));
            node = find_node(tlv + 4, 0);
            if(node)
                buffer_node_state(node, 1, from, NULL);
            break;
        }
        case 3: {
            struct neighbour *neigh;
            if(bodylen < 8) {
                fprintf(stderr, "Truncated NODE-ENDPOINT.\n");
                break;
            }
            if(have_id) {
                fprintf(stderr, "Duplicate NODE-ENDPOINT.\n");
                break;
            }
            memcpy(id, tlv + 4, 4);
            DO_NTOHL(eid, tlv + 8);
            debugf("   NODE-ENDPOINT %s %u\n", format_32(id), eid);
            if(id_eq(id, myid)) {
                fprintf(stderr, "Node id collision.\n");
                goto fail;
            }
            have_id = 1;
            if(unicast) {
                neigh = find_neighbour(interface, id, eid, from);
                if(neigh && unicast)
                    neigh->last_contact = now;
            }
            break;
        }
        case 4: {
            int rc;
            unsigned char h[8];
            struct neighbour *neigh = NULL;
            struct timespec t;

            if(have_id)
                neigh = find_neighbour(interface, id, eid, NULL);

            if(bodylen < 8) {
                fprintf(stderr, "Truncated NETWORK-STATE.\n");
                goto fail;
            }

            rc = network_hash(h);
            if(rc < 0) {
                fprintf(stderr, "Eek!\n");
                goto fail;
            }

            if(memcmp(h, tlv + 4, 8) == 0) {
                debugf("   NETWORK-STATE %s (consistent)\n",
                       format_64(tlv + 4));
                if(neigh)
                    neigh->last_contact = now;
                trickle_reset(&interface->trickle, 1);
                break;
            }

            debugf("   NETWORK-STATE %s (inconsistent, %s)\n",
                   format_64(tlv + 4), format_64(h));
            /* But don't reset Trickle. */

            ts_add_msec(&t, &interface->last_request_sent, HNCP_I_min);
            if(ts_compare(&now, &t) >= 0) {
                interface->last_request_sent = now;
                debugf("-> REQ-NETWORK-STATE\n");
                buffer_tlv(1, NULL, 0, from, NULL);
            }
            break;
        }
        case 5: {
            struct node *node;
            unsigned int seqno;
            int msecs, mine;
            int datalen = bodylen - 20;

            if(bodylen < 20) {
                fprintf(stderr, "Truncated NODE-STATE.\n");
                goto fail;
            }

            if(!have_id) {
                fprintf(stderr, "NODE-STATE with no NODE-ENDPOINT.\n");
            }

            DO_NTOHL(seqno, tlv + 8);
            DO_NTOHL(msecs, tlv + 12);

            debugf("   NODE-STATE %s %d %d", format_32(tlv + 4), seqno, msecs);

            mine = id_eq(tlv + 4, myid);
            if(mine)
                debugf(" (mine)");

            node = find_node(tlv + 4, 0);

            if(node && (seqno - node->seqno) & 0x80000000) {
                debugf(" (older)\n");
            } else if(!node || seqno != node->seqno ||
                      memcmp(tlv + 16, node->datahash, 8) != 0) {
                debugf(" (newer%s, %s)\n",
                       datalen ? ", data" : "", format_64(tlv + 16));

                if(mine) {
                    fprintf(stderr,
                            "Duplicate node identifier -- reclaiming.\n");
                    node->seqno = seqno + 42;
                    break;
                }

                if(datalen) {
                    unsigned char *new_data;
                    unsigned char h[8];
                    int rc;

                    node_hash(h, tlv + 24, datalen);
                    if(memcmp(h, tlv + 16, 8) != 0) {
                        fprintf(stderr, "Corrupt hash.\n");
                        goto fail;
                    }

                    if(!node)
                        node = find_node(tlv + 4, 1);
                    if(!node) {
                        fprintf(stderr, "Couldn't create node.\n");
                        goto fail;
                    }

                    new_data = realloc(node->data, datalen);
                    if(new_data == NULL) {
                        fprintf(stderr, "Eek!\n");
                        goto fail;
                    }
                    node->interface = interface;
                    node->seqno = seqno;
                    ts_add_msec(&node->orig_time, &now, msecs + 1);
                    node->data = new_data;
                    memcpy(node->data, tlv + 24, datalen);
                    node->datalen = datalen;
                    memcpy(node->datahash, tlv + 16, 8);
                    rc = parse_node_state(node);
                    if(rc < 0)
                        fprintf(stderr, "Couldn't parse node state.\n");
                    else
                        trickle_reset_all();
                    recompute = 1;
                } else {
                    struct neighbour *neigh = NULL;
                    if(have_id)
                        neigh = find_neighbour(interface, id, eid, from);
                    if(neigh) {
                        debugf("-> REQ-NODE-STATE %s\n", format_32(tlv + 4));
                        buffer_tlv(2, tlv + 4, 4, from, NULL);
                    } else
                        fprintf(stderr, "No neighbour to send request to.\n");
                }
            } else {
                debugf(" (consistent)\n");
            }
            break;
        }
        default:
            if(debug_level >= 3)
                debugf("   %d: %d\n", type, bodylen);
            break;
            break;
        }
        i += 4 + bodylen;
        i += -i & 3;
    }

    rc = 1;
    goto done;

 fail:
    rc = -1;

 done:
    if(recompute) {
        int r;
        silly_walk(find_node(myid, 0));
        prefix_assignment(1, &r);
        if(r)
            republish(0, 1);
    }
    return rc;
}

static void
parse_prefix(struct in6_addr *a, const unsigned char *p, int plen)
{
    unsigned char b[16];
    memset(b, 0, 16);
    memcpy(b, p, plen / 8);
    if(plen % 8 != 0)
        b[plen / 8] = (p[plen / 8] & ((0xFF << (8 - (plen % 8))) & 0xFF));
    memcpy(a, b, 16);
}

int
parse_node_state(struct node *node)
{
    const unsigned char *buf = node->data;
    int buflen = node->datalen;
    int i = 0, j, rc;
    struct node_neighbour *nn = NULL;
    int numnn = 0, maxnn = 0;
    struct external **exts = NULL;
    int numexts = 0, maxexts = 0;

    for(j = 0; j < numneighs; j++) {
        if(id_eq(neighs[j].id, node->id))
            neighs[j].keepalive_interval = 0;
    }

    while(i < buflen) {
        unsigned const char *tlv = buf + i;
        int type, bodylen;

        if(buflen - i < 4) {
            fprintf(stderr, "Received truncated TLV.\n");
            goto fail;
        }

        DO_NTOHS(type, tlv);
        DO_NTOHS(bodylen, tlv + 2);
        if(buflen - i < 4 + bodylen) {
            fprintf(stderr, "Received truncated TLV.\n");
            goto fail;
        }

        switch(type) {
        case 7:
            fprintf(stderr, "Received fragmented nonsense.\n");
            goto fail;
        case 8: {
            if(bodylen < 12) {
                fprintf(stderr, "Truncated neighbour TLV.\n");
                break;
            }

            if(numnn >= maxnn) {
                struct node_neighbour *nnn =
                    realloc(nn,
                            (2 * maxnn + 2) *
                            sizeof(struct node_neighbour));
                if(nnn == NULL) {
                    fprintf(stderr, "Eek.\n");
                    /* Oh, well. */
                    break;
                }
                nn = nnn;
                maxnn = 2 * maxnn + 2;
            }

            memcpy(nn[numnn].neigh, tlv + 4, 4);
            DO_NTOHL(nn[numnn].nei, tlv + 8);
            DO_NTOHL(nn[numnn].lei, tlv + 12);
            debugf("     NEIGHBOR %s (nei=%u, lei=%u)\n",
                   format_32(nn[numnn].neigh),
                   nn[numnn].nei, nn[numnn].lei);
            numnn++;
            break;
        }
        case 9: {
            unsigned eid, interval;
            if(bodylen < 8) {
                fprintf(stderr, "Truncated KEEP-ALIVE-INTERVAL.\n");
                break;
            }
            DO_NTOHL(eid, tlv + 4);
            DO_NTOHL(interval, tlv + 8);
            debugf("    KEEP-ALIVE-INTERVAL %u (eid=%u)\n", interval, eid);
            for(j = 0; j < numneighs; j++) {
                if(id_eq(neighs[j].id, node->id) && neighs[j].eid == eid)
                    neighs[j].keepalive_interval =
                        interval ? interval : 0xFFFFFFFF;
            }
            break;
        }
        case 32: {
            if(bodylen < 4) {
                debugf("Truncated VERSION\n");
                goto fail;
            }
            debugf("     VERSION %d\n", (int)tlv[4]);
            if(tlv[4] != 1) {
                fprintf(stderr, "Unexpected version.\n");
                goto fail;
            }
            break;
        }
        case 33: {
            struct external *ext;
            debugf("     EXTERNAL-CONNECTION\n");
            ext = parse_external(node, tlv + 4, bodylen);
            if(ext) {
                if(numexts >= maxexts) {
                    struct external **e =
                        realloc(exts,
                                (2 * maxexts + 2) * sizeof(struct external *));
                    if(e == NULL) {
                        fprintf(stderr, "Eek.\n");
                        break;
                    }
                    maxexts = 2 * maxexts + 2;
                    exts = e;
                }
                exts[numexts++] = ext;
            }
            break;
        }
        case 35: {
            unsigned char plen;
            struct in6_addr addr;
            int prio;
            unsigned int eid;
            struct prefix_list *pl;

            if(bodylen < 6) {
                fprintf(stderr, "Truncated ASSIGNED-PREFIX.\n");
                break;
            }
            DO_NTOHL(eid, tlv + 4);
            plen = *(tlv + 9);
            if(bodylen < 6 + (plen + 7) / 8) {
                fprintf(stderr, "Truncated ASSIGNED-PREFIX.\n");
                break;
            }
            prio = tlv[8] & 0x0F;
            parse_prefix(&addr, tlv + 10, plen);
            debugf("     ASSIGNED-PREFIX ");
            debug_address(&addr);
            debugf("/%d (%d, prio=%d)\n", plen, eid, prio);
            pl = prefix_list_cons(node->assigned,
                                  &addr, plen, node->id, eid, prio);
            if(pl)
                node->assigned = pl;
            break;
        }
        case 36: {
            unsigned int eid;
            struct prefix_list *pl;
            struct in6_addr addr;
            if(bodylen < 20) {
                fprintf(stderr, "Truncated NODE-ADDRESS.\n");
                break;
            }
            DO_NTOHL(eid, tlv + 4);
            memcpy(&addr, tlv + 8, 16);
            debugf("     NODE-ADDRESS ");
            debug_address(&addr);
            debugf(" %d\n",eid);
            pl = prefix_list_cons(node->addresses,
                                  &addr, 128, node->id, eid, 0);
            if(pl)
                node->addresses = pl;
            break;
        }
        default:
            if(debug_level >= 3)
                debugf("     %d: %d\n", type, bodylen);
            break;
        }
        i += 4 + bodylen;
        i += -i & 3;
    }

    rc = 1;
    goto done;

 fail:
    rc = -1;

 done:
    if(node->neighs)
        free(node->neighs);
    node->neighs = nn;
    node->numneighs = numnn;
    if(node->exts) {
        for(i = 0; i < node->numexts; i++)
            destroy_external(node->exts[i]);
        free(node->exts);
    }
    node->exts = exts;
    node->numexts = numexts;

    return rc;
}

struct external *
parse_external(struct node *node, const unsigned char *buf, int buflen)
{
    int i = 0;
    struct external *ext = calloc(1, sizeof(struct external));
    if(ext == NULL)
        return NULL;

    while(i < buflen) {
        unsigned const char *tlv = buf + i;
        int type, bodylen;

        if(buflen - i < 4) {
            fprintf(stderr, "Received truncated TLV.\n");
            goto fail;
        }

        DO_NTOHS(type, tlv);
        DO_NTOHS(bodylen, tlv + 2);
        if(buflen - i < 4 + bodylen) {
            fprintf(stderr, "Received truncated TLV.\n");
            goto fail;
        }

        switch(type) {
        case 34: {
            unsigned char plen;
            struct in6_addr addr;
            struct prefix_list *pl;
            if(bodylen < 9) {
                fprintf(stderr, "Truncated DELEGATED-PREFIX.\n");
                break;
            }
            plen = *(tlv + 12);
            if(bodylen < 9 + (plen + 7) / 8) {
                fprintf(stderr, "Truncated DELEGATED-PREFIX.\n");
                break;
            }
            parse_prefix(&addr, tlv + 13, plen);
            debugf("       DELEGATED-PREFIX ");
            debug_address(&addr);
            debugf("/%d\n", plen);
            /* XXX parse embedded TLVs. */
            pl = prefix_list_cons(ext->delegated, &addr, plen, node->id, 0, 0);
            if(pl != NULL)
                ext->delegated = pl;
            break;
        }
        case 37: {
            struct prefix_list *dns;
            debugf("       DHCPV6-DATA\n");
            dns = parse_dhcpv6(tlv + 4, bodylen, ext->dns);
            if(dns)
                ext->dns = dns;
            break;
        }
        case 38: {
            struct prefix_list *dns;
            debugf("       DHCPV4-DATA\n");
            dns = parse_dhcpv4(tlv + 4, bodylen, ext->dns);
            if(dns)
                ext->dns = dns;
            break;
        }
        default:
            if(debug_level >= 3)
                debugf("       %d: %d\n", type, bodylen);
            break;
        }
        i += 4 + bodylen;
        i += -i & 3;
    }

    return ext;

 fail:
    destroy_external(ext);
    return NULL;
}

struct prefix_list *
parse_dhcpv4(const unsigned char *buf, int buflen, struct prefix_list *dns)
{
    int i = 0;

    while(i < buflen) {
        unsigned const char *tlv = buf + i;
        int type, bodylen;

        if(buflen - i < 2) {
            fprintf(stderr, "Received truncated DHCPv4 TLV.\n");
            goto fail;
        }

        type = tlv[0];
        bodylen = tlv[1];

        switch(type) {
        case 0:
            i++;
            continue;
        case 6: {
            int j;
            struct in6_addr addr;
            struct prefix_list *pl;
            debugf("         Name Server ");
            for(j = 0; j < bodylen / 4; j++) {
                unsigned char a[16] =
                    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };
                memcpy(a + 12, tlv + i + 2 + j * 4, 4);
                memcpy(&addr, a, 16);
                debug_address(&addr);
                debugf(" ");
                pl = prefix_list_cons(dns, &addr, 128, NULL, 0, 0);
                if(pl != NULL)
                    dns = pl;
            }
            debugf("\n");
            break;
        }
        default:
            if(debug_level >= 3)
                debugf("         %d: %d\n", type, bodylen);
            break;
        }

        i += 2 + bodylen;
    }
    return dns;

 fail:
    return NULL;
}

struct prefix_list *
parse_dhcpv6(const unsigned char *buf, int buflen, struct prefix_list *dns)
{
    int i = 0;

    while(i < buflen) {
        unsigned const char *tlv = buf + i;
        int type, bodylen;

        if(buflen - i < 4) {
            fprintf(stderr, "Received truncated TLV.\n");
            goto fail;
        }

        DO_NTOHS(type, tlv);
        DO_NTOHS(bodylen, tlv + 2);
        if(buflen - i < 4 + bodylen) {
            fprintf(stderr, "Received truncated TLV.\n");
            goto fail;
        }

        switch(type) {
        case 23: {
            int j;
            struct in6_addr addr;
            struct prefix_list *pl;
            debugf("         OPTION_DNS_SERVERS ");
            for(j = 0; j < bodylen / 16; j++) {
                memcpy(&addr, tlv + i + 2 + j * 16, 16);
                debug_address(&addr);
                debugf(" ");
                pl = prefix_list_cons(dns, &addr, 128, NULL, 0, 0);
                if(pl != NULL)
                    dns = pl;
            }
            debugf("\n");
            break;
        }
        default:
            if(debug_level >= 3)
                debugf("         %d: %d\n", type, bodylen);
            break;
        }
        i += 4 + bodylen;
        i += -i & 3;
    }
    return dns;

 fail:
    return NULL;
}
