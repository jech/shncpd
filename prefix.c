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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "shncpd.h"
#include "trickle.h"
#include "state.h"
#include "prefix.h"
#include "util.h"
#include "kernel.h"

void
debug_address(const struct in6_addr *a)
{
    char b[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, a, b, sizeof(b));
    debugf("%s", b);
}

void
debug_prefix(const struct prefix *p)
{
    char b[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &p->p, b, sizeof(b));
    debugf("%s/%d", b, p->plen);
}

void
debug_prefix_list(const struct prefix_list *pl)
{
    int i;

    if(debug_level < 2 || !pl)
        return;

    for(i = 0; i < pl->numprefixes; i++) {
        debug_prefix(&pl->prefixes[i]);
        if(i < pl->numprefixes - 1)
            debugf(" ");
    }
}

struct prefix_list *
create_prefix_list()
{
    return calloc(1, sizeof(struct prefix_list));
}

void
destroy_prefix_list(struct prefix_list *pl)
{
    if(pl == NULL)
        return;
    free(pl->prefixes);
    free(pl);
}

struct prefix_list *
prefix_list_cons_prefix(struct prefix_list *pl, const struct prefix *p)
{
    if(pl == NULL)
        pl = create_prefix_list();
    if(pl == NULL)
        return NULL;
    if(pl->numprefixes >= pl->maxprefixes) {
        struct prefix *n =
            realloc(pl->prefixes,
                    (pl->maxprefixes * 2 + 2) * sizeof(struct prefix));
        if(n == NULL)
            return NULL;
        pl->prefixes = n;
        pl->maxprefixes = pl->maxprefixes * 2 + 2;
    }
    pl->prefixes[pl->numprefixes++] = *p;
    return pl;
}

struct prefix_list *
prefix_list_cons(struct prefix_list *pl,
                 const struct in6_addr *a, int plen,
                 const unsigned char *id, unsigned int eid, int prio)
{
    struct prefix p;

    p.p = *a;
    p.plen = plen;
    if(id)
        memcpy(p.id, id, 4);
    else
        memset(p.id, 0, 4);
    p.eid = eid;
    p.prio = prio;
    return prefix_list_cons_prefix(pl, &p);
}

struct prefix_list *
prefix_list_remove(struct prefix_list *pl, int i)
{
    assert(i >= 0 && i < pl->numprefixes);
    memmove(pl->prefixes + i, pl->prefixes + i + 1,
            sizeof(struct prefix) * (pl->numprefixes - i - 1));
    pl->numprefixes--;
    MEM_UNDEFINED(pl->prefixes + pl->numprefixes,
                  sizeof(struct prefix));
    return pl;
}

struct prefix_list*
prefix_list_append(struct prefix_list *p1, struct prefix_list *p2)
{
    int i;

    if(p1 == NULL)
        return p2;

    for(i = 0; i < p2->numprefixes; i++) {
        struct prefix_list *pl = prefix_list_cons_prefix(p1, &p2->prefixes[i]);
        if(pl == NULL)
            return NULL;
    }
    destroy_prefix_list(p2);
    return p1;
}

int
prefix_list_member(const struct prefix *p, const struct prefix_list *pl)
{
    int i;
    for(i = 0; i < pl->numprefixes; i++) {
        struct prefix *q = &pl->prefixes[i];
        if(p->plen == q->plen && memcmp(&p->p, &q->p, 16) == 0)
            return 1;
    }
    return 0;
}

int
prefix_list_within(const struct prefix *p, const struct prefix_list *pl)
{
    unsigned char pp[16];
    int i;

    memcpy(pp, &p->p, 16);

    for(i = 0; i < pl->numprefixes; i++) {
        struct prefix *q = &pl->prefixes[i];
        unsigned char qq[16];

        if(p->plen < q->plen)
            continue;

        memcpy(qq, &q->p, 16);

        if(memcmp(pp, qq, q->plen / 8) != 0)
            continue;

        if(q->plen % 8 == 0) {
            return 1;
        } else {
            int i = q->plen / 8 + 1;
            unsigned char mask = (0xFF << (q->plen % 8)) & 0xFF;
            if((pp[i] & mask) == (qq[i] & mask)) {
                return 1;
            }
        }
    }
    return 0;
}

int
prefix_list_overlap(const struct prefix *p, const struct prefix_list *pl)
{
    unsigned char pp[16];
    int i;

    memcpy(pp, &p->p, 16);

    for(i = 0; i < pl->numprefixes; i++) {
        struct prefix *q = &pl->prefixes[i];
        int plen = min(p->plen, q->plen);
        unsigned char qq[16];

        memcpy(qq, &q->p, 16);

        if(memcmp(pp, qq, plen / 8) != 0)
            continue;

        if(plen % 8 == 0) {
            return 1;
        } else {
            int i = plen / 8 + 1;
            unsigned char mask = (0xFF << (plen % 8)) & 0xFF;
            if((pp[i] & mask) == (qq[i] & mask)) {
                return 1;
            }
        }
    }
    return 0;
}

int
prefix_valid(const struct prefix *p,
             const struct prefix_list *in, const struct prefix_list *out)
{
    return prefix_list_overlap(p, in) && !prefix_list_overlap(p, out);
}

void
random_bits(unsigned char *buf, int first, int len)
{
    int i;

    if(first % 8 != 0) {
        unsigned char mask = (0xFF >> (first % 8)) ^ 0xFF;
        buf[first / 8] &= mask;
        buf[first / 8] |= random() & (0xFF ^ mask);
    }

    for(i = (first + 7) / 8; i < (first + len) / 8; i++)
        buf[i] = random() % 0xFF;

    if((first + len) % 8 != 0) {
        unsigned char mask = 0xFF >> ((first + len) % 8);
        buf[(first + len) / 8] &= mask;
        buf[(first + len) / 8] |= random() & (0xFF ^ mask);
    }
}

int
random_prefix(struct prefix *res, int plen, int zero_bits, int tweak_v6,
              const struct prefix *in, const struct prefix_list *out)
{
    unsigned char pp[16];
    int i;
    struct prefix p;

    if(in->plen + zero_bits > plen)
        return 0;

    for(i = 0; i < 20; i++) {
        memset(pp, 0, 16);
        memcpy(pp, &in->p, 16);
        random_bits(pp, in->plen + zero_bits, plen);
        if(tweak_v6 && in->plen <= 68)
            pp[8] &= ~3;

        memcpy(&p.p, pp, 16);
        p.plen = plen;
        if(!prefix_list_overlap(&p, out)) {
            *res = p;
            return 1;
        }
    }

    return 0;
}

static int
prefix_v4(struct prefix *p)
{
    return p->plen >= 96 && IN6_IS_ADDR_V4MAPPED(&p->p);
}

struct prefix_list *
all_assigned_prefixes()
{
    int i, j;
    struct prefix_list *pl = create_prefix_list(), *pl2;
    if(pl == NULL)
        return NULL;

    for(i = 0; i < numnodes; i++) {
        if(nodes[i].assigned == NULL)
            continue;
        for(j = 0; j < nodes[i].assigned->numprefixes; j++) {
            pl2 = prefix_list_cons_prefix(pl, &nodes[i].assigned->prefixes[j]);
            if(pl2 == NULL) {
                destroy_prefix_list(pl);
                return NULL;
            }
            pl = pl2;
        }
    }
    return pl;
}

struct prefix_list *
link_assigned_prefixes(int eid)
{
    int i, j;
    struct prefix_list *pl = create_prefix_list(), *pl2;
    if(pl == NULL)
        return NULL;

    for(i = 0; i < numneighs; i++) {
        struct node *node;
        unsigned int his_id = ~0;
        if(neighs[i].interface->ifindex != eid)
            continue;
        node = find_node(neighs[i].id, 0);
        if(node == NULL || node->neighs == NULL || node->assigned == NULL)
            continue;
        for(j = 0; j < node->numneighs; j++)
            if(id_eq(node->neighs[j].neigh, myid)) {
                his_id = node->neighs[j].lei;
                break;
            }
        if(j == node->numneighs)
            continue;

        for(j = 0; j < node->assigned->numprefixes; j++) {
            struct prefix *p;
            if(node->assigned == NULL)
                continue;
            p = &node->assigned->prefixes[j];
            if(p->eid == his_id) {
                pl2 = prefix_list_cons_prefix(pl, p);
                if(pl2 == NULL) {
                    destroy_prefix_list(pl);
                    return NULL;
                }
                pl = pl2;
            }
        }
    }
    return pl;
}

struct prefix_list *
all_delegated_prefixes()
{
    int i, j, k;
    struct prefix_list *pl = create_prefix_list(), *pl2;
    if(pl == NULL)
        return NULL;

    for(i = 0; i < numnodes; i++) {
        for(j = 0; j < nodes[i].numexts; j++) {
            if(nodes[i].exts[j]->delegated == NULL)
                continue;
            for(k = 0; k < nodes[i].exts[j]->delegated->numprefixes; k++) {
                struct prefix *p = &nodes[i].exts[j]->delegated->prefixes[k];
                pl2 = prefix_list_cons_prefix(pl, p);
                if(pl2 == NULL) {
                    destroy_prefix_list(pl);
                    return NULL;
                }
                if(pl2 == NULL) {
                    destroy_prefix_list(pl);
                    return NULL;
                }
                pl = pl2;
            }
        }
    }
    return pl;
}

struct prefix_list *
all_node_addresses()
{
    int i, j;
    struct prefix_list *pl = create_prefix_list(), *pl2;
    if(pl == NULL)
        return NULL;

    for(i = 0; i < numnodes; i++) {
        if(nodes[i].addresses == NULL || id_eq(nodes[i].id, myid))
            continue;
        for(j = 0; j < nodes[i].addresses->numprefixes; j++) {
            struct prefix *p = &nodes[i].addresses->prefixes[j];
            pl2 = prefix_list_cons_prefix(pl, p);
            if(pl2 == NULL) {
                destroy_prefix_list(pl);
                return NULL;
            }
            pl = pl2;
        }
    }
    return pl;
}

int
address_assignment()
{
    int i, j;
    struct prefix_list *addresses = all_node_addresses();
    int republish = 0;

    for(i = 0; i < numinterfaces; i++) {
        struct interface *interface = &interfaces[i];
        struct prefix_list *assigned =
            link_assigned_prefixes(interface->ifindex);
        int rc;

        j = 0;
        while(interface->assigned_addresses &&
              j < interface->assigned_addresses->numprefixes) {
            int rc;
            struct prefix p = interface->assigned_addresses->prefixes[j];
            p.plen = 128;
            if(!prefix_valid(&p, assigned, addresses)) {
                debugf("Removing address ");
                debug_prefix(&interface->assigned_addresses->prefixes[j]);
                debugf("from interface %s.\n", interface->ifname);

                rc = kernel_address(interface->ifindex, interface->ifname,
                                    &p.p, p.plen,                0);
                if(rc < 0)
                    fprintf(stderr, "Couldn't remove address.\n");
                    interface->assigned_addresses =
                        prefix_list_remove(interface->assigned_addresses, j);
            } else {
                j++;
            }
        }

        for(j = 0; j < assigned->numprefixes; j++) {
            struct prefix p;
            struct prefix_list *pl;

            if(interface->assigned_addresses &&
               prefix_list_overlap(&assigned->prefixes[j],
                                   interface->assigned_addresses))
                continue;

            rc = random_prefix(&p, 128, 2, 0,
                               &assigned->prefixes[j], addresses);
            if(rc <= 0)
                continue;
            p.plen = assigned->prefixes[j].plen;
            debugf("Adding address ");
            debug_prefix(&p);
            debugf("to interface %s.\n", interface->ifname);
            rc = kernel_address(interface->ifindex, interface->ifname,
                                &p.p, p.plen, 1);
            if(rc < 0) {
                perror("Couldn't assign address");
                continue;
            }

            pl = prefix_list_cons_prefix(interface->assigned_addresses, &p);
            if(pl)
                interface->assigned_addresses = pl;
        }
        destroy_prefix_list(assigned);
    }
    destroy_prefix_list(addresses);
    return republish;
}

void
address_assignment_cleanup()
{
    int i, rc;
    for(i = 0; i < numinterfaces; i++) {
        struct interface *interface = &interfaces[i];
        while(interface->assigned_addresses &&
              interface->assigned_addresses->numprefixes > 0) {
            debugf("Removing address ");
            debug_prefix(&interface->assigned_addresses->prefixes[0]);
            debugf("from interface %s.\n", interfaces->ifname);
            rc = kernel_address(interface->ifindex, interface->ifname,
                                &interface->assigned_addresses->prefixes[0].p,
                                interface->assigned_addresses->prefixes[0].plen,
                                0);
            if(rc < 0)
                fprintf(stderr, "Couldn't remove address.\n");
            interface->assigned_addresses =
                prefix_list_remove(interface->assigned_addresses, 0);
        }
    }
}

int
prefix_assignment(int changed, int *republish)
{
    int r = 0;

    if(changed) {
        if(addr_assign)
            r |= !!address_assignment();
    }

    if(republish)
        *republish = r;
    return 1800 * 1000;
}

void
prefix_assignment_cleanup()
{
    address_assignment_cleanup();
}
