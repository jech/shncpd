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
#include <errno.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "shncpd.h"
#include "trickle.h"
#include "state.h"
#include "prefix.h"
#include "ra.h"
#include "util.h"
#include "kernel.h"

static const unsigned char v4prefix[16] =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };

char *
format_address(const struct in6_addr *a, char *buf, int buflen)
{
    char *ptr;

    if(IN6_IS_ADDR_V4MAPPED(a))
        ptr = (char*)inet_ntop(AF_INET, (unsigned char*)a + 12, buf, buflen);
    else
        ptr = (char*)inet_ntop(AF_INET6, a, buf, buflen);

    if(ptr == NULL)
        snprintf(buf, buflen, "%s", strerror(errno));
    buf[buflen - 1] = '\0';
    return ptr;
}

char *
format_prefix_raw(const struct in6_addr *a, int plen, char *buf, int buflen)
{
    char *ptr;
    int len;
    int v4 = plen > 96 && IN6_IS_ADDR_V4MAPPED(a);

    if(v4)
        ptr = (char*)inet_ntop(AF_INET, (unsigned char*)&a + 12,
                               buf, buflen);
    else
        ptr = (char*)inet_ntop(AF_INET6, a, buf, buflen);

    if(ptr == NULL)
        snprintf(buf, buflen, "%s", strerror(errno));
    buf[buflen - 1] = '\0';

    len = strlen(buf);
    snprintf(buf + len, buflen - len, "/%d", v4 ? plen - 96 : plen);
    buf[buflen - 1] = '\0';

    return ptr;
}

char *
format_prefix(const struct prefix *p, char *buf, int buflen)
{
    return format_prefix_raw(&p->p, p->plen, buf, buflen);
}

void
debug_address(const struct in6_addr *a)
{
    char b[INET6_ADDRSTRLEN];
    format_address(a, b, sizeof(b));
    debugf("%s", b);
}

void
debug_prefix_raw(const struct in6_addr *a, int plen)
{
    char b[INET6_ADDRSTRLEN];
    format_prefix_raw(a, plen, b, sizeof(b));
    debugf("%s", b);
}

void
debug_prefix(const struct prefix *p)
{
    char b[INET6_ADDRSTRLEN + 8];
    format_prefix(p, b, sizeof(b));
    debugf("%s", b);
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

int
parse_prefix(const char *string, struct prefix *p)
{
    char buf[INET6_ADDRSTRLEN];
    int rc, plen;
    char *slash;
    struct in_addr ina;
    struct in6_addr ina6;

    memset(p, 0, sizeof(struct prefix));

    if(strcmp(string, "default") == 0) {
        return 1;
    }

    strncpy(buf, string, INET6_ADDRSTRLEN);
    buf[INET6_ADDRSTRLEN - 1] = '\0';

    slash = strchr(buf, '/');
    if(slash == NULL) {
        plen = -1;
    } else {
        char *end;
        plen = strtol(slash + 1, &end, 0);
        if(*end != '\0' || plen < 0 || plen > 128)
            return -1;
        *slash = '\0';
    }

    rc = inet_pton(AF_INET, buf, &ina);
    if(rc > 0) {
        memcpy(&p->p, v4prefix, 12);
        memcpy((char*)&p->p + 12, &ina, 4);
        p->plen = plen < 0 ? 128 : plen + 96;
    } else {
        rc = inet_pton(AF_INET6, buf, &ina6);
        if(rc < 1)
            return -1;
        memcpy(&p->p, &ina6, 16);
        p->plen = plen < 0 ? 128 : plen;
    }
    return 1;
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
prefix_eq(const struct prefix *p, const struct prefix *q)
{
    return p->plen == q->plen && memcmp(&p->p, &q->p, 16) == 0;
}

int
prefix_list_member(const struct prefix *p, const struct prefix_list *pl)
{
    int i;
    if(pl == NULL)
        return 0;

    for(i = 0; i < pl->numprefixes; i++) {
        struct prefix *q = &pl->prefixes[i];
        if(prefix_eq(p, q))
            return 1;
    }
    return 0;
}

int
prefix_takes_precedence(const struct prefix *p, const struct prefix *q)
{
    if(p->prio > q->prio)
        return 1;
    if(p->prio == q->prio && memcmp(p->id, q->id, 4) > 0)
        return 1;
    return 0;
}

int
prefix_within(const struct prefix *p, const struct prefix *q)
{
    unsigned char pp[16], qq[16];

    if(p->plen < q->plen)
        return 0;

    memcpy(pp, &p->p, 16);
    memcpy(qq, &q->p, 16);

    if(memcmp(pp, qq, q->plen / 8) != 0)
        return 0;

    if(q->plen % 8 == 0) {
        return 1;
    } else {
        int i = q->plen / 8 + 1;
        unsigned char mask = (0xFF << (q->plen % 8)) & 0xFF;
        if((pp[i] & mask) == (qq[i] & mask)) {
            return 1;
        }
    }

    return 0;
}

int
prefix_within_v4(const unsigned char *p4, const struct prefix *q)
{
    struct prefix p;
    memset(&p, 0, sizeof(p));
    memcpy(&p.p, v4prefix, 12);
    memcpy(((unsigned char*)&p.p) + 12, p4, 4);
    p.plen = 128;

    return prefix_within(&p, q);
}


int
prefix_overlaps(const struct prefix *p, const struct prefix *q)
{
    if(p->plen >= q->plen)
        return prefix_within(p, q);
    else
        return prefix_within(q, p);
}

int
prefix_list_within(const struct prefix *p, const struct prefix_list *pl)
{
    int i;

    if(pl == NULL)
        return 0;

    for(i = 0; i < pl->numprefixes; i++) {
        if(prefix_within(p, &pl->prefixes[i]))
            return 1;
    }

    return 0;
}

int
prefix_list_within_v4(const unsigned char *p4, const struct prefix_list *pl)
{
    struct prefix p;
    memset(&p, 0, sizeof(p));
    memcpy(&p.p, v4prefix, 12);
    memcpy(((unsigned char*)&p.p) + 12, p4, 4);
    p.plen = 128;

    return prefix_list_within(&p, pl);
}

int
prefix_list_overlap(const struct prefix *p, const struct prefix_list *pl,
                    int respect_precedence)
{
    unsigned char pp[16];
    int i;

    memcpy(pp, &p->p, 16);

    if(pl == NULL)
        return 0;

    for(i = 0; i < pl->numprefixes; i++) {
        struct prefix *q = &pl->prefixes[i];
        int plen = min(p->plen, q->plen);
        unsigned char qq[16];

        if(respect_precedence &&
           ((id_eq(p->id, q->id) && p->eid == q->eid) ||
            prefix_takes_precedence(p, q)))
            continue;

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
             const struct prefix_list *pl1, const struct prefix_list *pl2)
{
    if(pl1 && prefix_list_overlap(p, pl1, 1))
        return 0;
    if(pl2 && prefix_list_overlap(p, pl2, 1))
        return 0;
    return 1;
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
random_prefix(struct prefix *res,
              int plen, int zero_bits, int tweak_v6,
              const struct prefix *in, const struct prefix_list *out)
{
    unsigned char pp[16];
    int i;
    struct prefix p;

    if(plen > 128)
        plen = 128;

    if(in->plen + zero_bits > plen)
        return 0;

    for(i = 0; i < 20; i++) {
        memset(pp, 0, 16);
        memcpy(pp, &in->p, 16);
        random_bits(pp, in->plen + zero_bits, (plen - (in->plen + zero_bits)));
        if(tweak_v6 && in->plen <= 68)
            pp[8] &= ~3;

        memcpy(&p.p, pp, 16);
        p.plen = plen;
        if(!prefix_list_overlap(&p, out, 0)) {
            *res = p;
            return 1;
        }
    }

    return 0;
}

int
prefix_v4(const struct prefix *p)
{
    return p->plen >= 96 && IN6_IS_ADDR_V4MAPPED(&p->p);
}

int
generate_random_v4(unsigned char *ip, const struct prefix_list *pl)
{
    int start, i, rc;
    struct prefix p;

    if(pl == NULL)
        return -1;

    start = random() % pl->numprefixes;

    for(i = 0; i < pl->numprefixes; i++) {
        int j = (start + i) % pl->numprefixes;
        if(prefix_v4(&pl->prefixes[j]) && pl->prefixes[j].plen <= 126) {
            rc = random_prefix(&p, 128, 0, 0, &pl->prefixes[j], NULL);
            if(rc >= 0) {
                memcpy(ip, (unsigned char*)&p.p + 12, 4);
                return 1;
            }
        }
    }
    return -1;
}

int
interface_v4(struct interface *interface, unsigned char *v4_return)
{
    int i;

    for(i = 0; i < interface->numassigned; i++) {
        struct in6_addr *a = &interface->assigned[i].assigned_address;
        if(IN6_IS_ADDR_V4MAPPED(a)) {
            memcpy(v4_return, (unsigned char*)a + 12, 4);
            return 1;
        }
    }
    return 0;
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
link_assigned_prefixes(struct interface *interface,
                       const struct prefix *overlaps)
{
    int i, j;
    struct prefix_list *pl;

    if(interface->type == INTERFACE_ADHOC)
        return NULL;

    pl = create_prefix_list();
    if(pl == NULL)
        return NULL;

    for(i = 0; i < numneighs; i++) {
        struct node *node;
        unsigned int his_id = ~0;
        if(neighs[i].interface->ifindex != interface->ifindex)
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
            if(p->eid == his_id &&
               (!overlaps || prefix_overlaps(p, overlaps))) {
                struct prefix_list *pl2;
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
best_prefix(const struct prefix *delegated, int eid,
            const struct prefix *assigned,
            const struct prefix_list *link_assigned,
            struct prefix *best_return)
{
    struct prefix *best = NULL;
    int i;

    if(link_assigned) {
        for(i = 0; i < link_assigned->numprefixes; i++) {
            struct prefix *p = &link_assigned->prefixes[i];
            if(!prefix_within(p, delegated) && !prefix_within(delegated, p))
                continue;
            if(best && prefix_takes_precedence(best, p))
                continue;

            best = p;
        }
    }

    if(!best)
        return 0;

    if(assigned && prefix_takes_precedence(assigned, best))
        return 0;

    *best_return = *best;
    return 1;
}

int
publish_prefix(struct interface *interface, struct assigned_prefix *ap,
               int publish)
{
    if(publish) {
        memcpy(ap->assigned.id, myid, 4);
        ap->published = 1;
    } else {
        ap->published = 0;
    }

    return 1;
}

int
route_externals(struct external **ext, int numexternals, int add)
{
    int i, j, rc = 1;
    struct in6_addr def;
    struct in6_addr v4_def;
    memset(&def, 0, sizeof(def));
    memcpy(&v4_def, v4prefix, 16);
    for(i = 0; i < numexternals; i++) {
        for(j = 0; j < ext[i]->delegated->numprefixes; j++) {
            struct prefix *p = &ext[i]->delegated->prefixes[j];
            int rrc;
            if(prefix_v4(p)) {
                rrc = kernel_route(0, NULL, &v4_def, 96, NULL, 0, add);
                rrc = kernel_route(0, NULL, &p->p, p->plen, NULL, 0, add);
            } else {
                rrc = kernel_route(0, NULL, &def, 0, &p->p, p->plen, add);
                rrc = kernel_route(0, NULL, &p->p, p->plen, NULL, 0, add);
            }
            if(rrc < 0)
                rc = rrc;
        }
    }
    return rc;
}

int
destroy_assigned_address(struct interface *interface,
                         struct assigned_prefix *ap)
{
    int rc = 0;

    if(IN6_IS_ADDR_UNSPECIFIED(&ap->assigned_address))
        return 0;

    debugf("Removing address ");
    debug_address(&ap->assigned_address);
    debugf(" from %s.\n", interface->ifname);

    assert(ap->assigned.plen > 0 && ap->applied);

    if(interface->ifindex > 0) {
        rc = kernel_address(interface->ifindex, interface->ifname,
                            &ap->assigned_address, ap->assigned.plen, 0);
        if(rc < 0)
            fprintf(stderr, "Couldn't remove address.\n");
    }

    return rc;
}

int
destroy_assigned(struct interface *interface, struct assigned_prefix *ap)
{
    if(ap->applied) {
        destroy_assigned_address(interface, ap);

        debugf("Removing prefix ");
        debug_prefix(&ap->assigned);
        debugf(" from %s.\n", interface->ifname);

        assert(ap->assigned.plen > 0);
        if(interface->ifindex > 0)
            kernel_route(interface->ifindex, interface->ifname,
                         &ap->assigned.p, ap->assigned.plen, NULL, 0, 0);
        ap->applied = 0;
        ra_retract(&ap->assigned);
        schedule_ra(NULL, 1, 0);
    }
    ts_zero(&ap->apply_timer);
    publish_prefix(interface, ap, 0);
    memset(&ap->assigned, 0, sizeof(ap->assigned));
    return 1;
}

struct assigned_prefix *
find_assigned(struct interface *interface, const struct prefix *delegated,
              int create)
{
    struct assigned_prefix *new;
    int i;

    for(i = 0; i < interface->numassigned; i++) {
        if(prefix_eq(&interface->assigned[i].delegated, delegated))
            return &interface->assigned[i];
    }

    if(!create)
        return NULL;

    new = realloc(interface->assigned,
                  (interface->numassigned + 1) *
                  sizeof(struct assigned_prefix));
    if(new == NULL)
        return NULL;
    interface->assigned = new;

    memset(&interface->assigned[interface->numassigned], 0,
           sizeof(struct assigned_prefix));
    interface->assigned[interface->numassigned].delegated = *delegated;
    return &interface->assigned[interface->numassigned++];
}

void
flush_assigned(struct interface *interface, struct assigned_prefix *ap)
{
    int n = ap - interface->assigned;
    assert(n >= 0 && n < interface->numassigned);

    destroy_assigned(interface, ap);
    if(n < interface->numassigned - 1)
        interface->assigned[n] =
            interface->assigned[interface->numassigned - 1];
    interface->numassigned--;

    if(interface->numassigned == 0) {
        free(interface->assigned);
        interface->assigned = NULL;
    }
}

static int
select_plen(struct prefix *delegated)
{
    if(prefix_v4(delegated))
        return min(126, max(120, delegated->plen + 4));
    else
        return 64;
}

int
prefix_assignment_1(struct interface *interface,
                    struct assigned_prefix *ap,
                    int backoff_triggered,
                    const struct prefix_list *all_assigned,
                    const struct prefix_list *link_assigned)
{
    struct prefix best;
    int have_best, have_assigned, rc;
    int republish = 0;

 again:

    have_assigned = ap->assigned.plen > 0;
    have_best =
        best_prefix(&ap->delegated, interface->ifindex,
                    have_assigned && ap->published ? &ap->assigned : NULL,
                    link_assigned, &best);

    if(backoff_triggered && have_assigned) {
        if(!ap->published) {
            ap->published = 1;
            republish = 1;
        }
        if(!ap->applied)
            ts_add_msec(&ap->apply_timer, &now, 2 * FLOODING_DELAY);
    } else if(!have_best && !have_assigned) {
        if(ap->backoff_timer.tv_sec == 0) {
            if(!backoff_triggered) {
                ts_add_random(&ap->backoff_timer, &now, BACKOFF_MAX_DELAY);
            } else {
                rc = random_prefix(&ap->assigned, select_plen(&ap->delegated),
                                   0, 1,
                                   &ap->delegated, all_assigned);
                if(rc > 0) {
                    ap->assigned.prio = 2;
                    memcpy(ap->assigned.id, myid, 4);
                    ap->assigned.eid = interface->ifindex;
                    ts_add_msec(&ap->apply_timer, &now, 2 * FLOODING_DELAY);
                    rc = publish_prefix(interface, ap, 1);
                    if(rc < 0) {
                        fprintf(stderr, "Couldn't publish prefix.\n");
                        memset(&ap->assigned, 0, sizeof(ap->assigned));
                    }
                    republish = 1;
                } else {
                    fprintf(stderr, "Couldn't draw random prefix.\n");
                }
                ap->applied = 0;
            }
        }
    } else if(have_best && !have_assigned) {
        ts_zero(&ap->backoff_timer);
        ap->assigned = best;
        publish_prefix(interface, ap, 0);
        ts_add_msec(&ap->apply_timer, &now, 2 * FLOODING_DELAY);
    } else if(!have_best && have_assigned) {
        if(!prefix_valid(&ap->assigned, all_assigned, link_assigned)) {
            destroy_assigned(interface, ap);
            backoff_triggered = 0;
            goto again;
        }

        if(!ap->published) {
            /* Adopt. */
            ts_zero(&ap->apply_timer);
            ap->assigned.prio = 2;
            backoff_triggered = 1;
            goto again;
        }
    } else {
        ts_zero(&ap->backoff_timer);
        if(prefix_eq(&best, &ap->assigned)) {
            publish_prefix(interface, ap, 0);
            if(!ap->applied && ap->apply_timer.tv_sec == 0) {
                ts_add_msec(&ap->apply_timer, &now, 2 * FLOODING_DELAY);
            }
        } else {
            destroy_assigned(interface, ap);
            goto again;
        }
    }

    return republish;
}

int
address_assignment_1(struct interface *interface,
                     struct assigned_prefix *ap,
                     struct prefix_list *addresses)
{
    int have_assigned = ap->assigned.plen > 0;
    int have_address = !IN6_IS_ADDR_UNSPECIFIED(&ap->assigned_address);
    struct prefix p = {.p = ap->assigned_address, .plen = 128};
    int rc;
    int republish = 0;

    if(have_address && (!have_assigned ||
                        !prefix_within(&p, &ap->assigned) ||
                        prefix_list_overlap(&p, addresses, 0))) {
        destroy_assigned_address(interface, ap);
        memset(&ap->assigned_address, 0, 16);
        have_address = 0;
        republish = 1;
    }

    if(have_address || !have_assigned)
        return republish;

    rc = random_prefix(&p, 128, 2, 0, &ap->assigned, addresses);
    if(rc <= 0) {
        fprintf(stderr, "Couldn't generate random address.\n");
        return republish;
    }

    debugf("Adding address ");
    debug_address(&p.p);
    debugf(" to interface %s.\n", interface->ifname);
    rc = kernel_address(interface->ifindex, interface->ifname,
                        &p.p, ap->assigned.plen, 1);
    if(rc >= 0) {
        ap->assigned_address = p.p;
        republish = 1;
    } else {
        perror("Couldn't assign address");
    }

    return republish;
}

int
prefix_assignment(int changed)
{
    struct prefix_list *delegated = all_delegated_prefixes();
    struct prefix_list *addresses = all_node_addresses();
    int i, j;
    int republish = 0;
    struct timespec again;

    if(changed) {
        for(i = 0; i < numinterfaces; i++) {
            /* Flush any delegated prefixes that have disappeared. */
            j = 0;
            while(j < interfaces[i].numassigned) {
                if(interfaces[i].ifindex == 0 ||
                   !prefix_list_member(&interfaces[i].assigned[j].delegated,
                                       delegated))
                    flush_assigned(&interfaces[i], &interfaces[i].assigned[j]);
                else
                    j++;
            }
            /* Add any delegated prefixes that have appeared. */
            for(j = 0; j < delegated->numprefixes; j++) {
                struct assigned_prefix *ap =
                    find_assigned(&interfaces[i],
                                  &delegated->prefixes[j], 1);
                if(ap == NULL)
                    continue;
            }
        }
    }

    again = now;
    again.tv_sec += 120;

    for(i = 0; i < numinterfaces; i++) {
        for(j = 0; j < interfaces[i].numassigned; j++) {
            struct assigned_prefix *ap = &interfaces[i].assigned[j];
            struct prefix_list *link_assigned =
                link_assigned_prefixes(&interfaces[i], &ap->delegated);
            struct prefix_list *all_assigned = all_assigned_prefixes();
            int bt =
                ap->backoff_timer.tv_sec > 0 &&
                ts_compare(&now, &ap->backoff_timer) > 0;
            int rc;
            if(changed || bt) {
                if(!changed)
                    ts_zero(&ap->backoff_timer);
                rc = prefix_assignment_1(&interfaces[i],
                                         &interfaces[i].assigned[j],
                                         !changed,
                                         all_assigned, link_assigned);
                republish = republish || rc;
            }

            if(ap->apply_timer.tv_sec > 0 &&
               ts_compare(&now, &ap->apply_timer) > 0) {
                debugf("Adding prefix ");
                debug_prefix(&ap->assigned);
                debugf(" to interface %s.\n", interfaces[i].ifname);
                rc = kernel_route(interfaces[i].ifindex, interfaces[i].ifname,
                                  &ap->assigned.p, ap->assigned.plen,
                                  NULL, 0, 1);
                if(rc >= 0) {
                    ap->applied = 1;
                    republish = 1;
                    schedule_ra(NULL, 1, 0);
                    rc = address_assignment_1(&interfaces[i], ap, addresses);
                    republish = republish || rc;
                } else {
                    fprintf(stderr, "Couldn't apply prefix.\n");
                }
                ts_zero(&ap->apply_timer);
            }

            ts_min(&again, &ap->backoff_timer);
            ts_min(&again, &ap->apply_timer);

            destroy_prefix_list(all_assigned);
            destroy_prefix_list(link_assigned);
        }
    }

    destroy_prefix_list(delegated);
    destroy_prefix_list(addresses);

    prefix_assignment_time = again;
    return republish;
}

void
prefix_assignment_cleanup()
{
    int i;
    for(i = 0; i < numinterfaces; i++) {
        while(interfaces[i].numassigned > 0)
            flush_assigned(&interfaces[i], &interfaces[i].assigned[0]);
    }
}
