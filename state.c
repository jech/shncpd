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

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/in.h>

#include "shncpd.h"
#include "trickle.h"
#include "state.h"
#include "send.h"
#include "prefix.h"
#include "util.h"

#ifdef USE_LIBUBOX
#include <libubox/md5.h>
#define MD5Init(ctx) md5_begin(ctx)
#define MD5Final(x,ctx) md5_end(x,ctx)
#define MD5Update(ctx,x,y) md5_hash(x,y,ctx)
#define MD5_CTX md5_ctx_t
#elif USE_OPENSSL
#include <openssl/md5.h>
#define MD5Init(ctx) MD5_Init(ctx)
#define MD5Final(x,ctx) MD5_Final(x,ctx)
#define MD5Update(ctx,x,y) MD5_Update(ctx,x,y)
#else
#include <bsd/md5.h>
#endif

struct interface interfaces[MAXINTERFACES];
int numinterfaces = 0;

struct node nodes[MAXNODES];
int numnodes = 0;

struct neighbour neighs[MAXNEIGHS];
int numneighs = 0;

void
trickle_reset_all()
{
    int i;
    for(i = 0; i < numinterfaces; i++)
        trickle_reset(&interfaces[i].trickle, 0);
}

struct interface *
find_interface(int ifindex)
{
    int i;
    for(i = 0; i < numinterfaces; i++) {
        if(interfaces[i].ifindex <= 0)
            continue;
        if(interfaces[i].ifindex == ifindex)
            return &interfaces[i];
    }
    return NULL;
}

struct neighbour *
find_neighbour(struct interface *interface, const unsigned char *id,
               unsigned int eid, const struct sockaddr_in6 *create)
{
    int i;

    if(id_eq(id, myid)) {
        fprintf(stderr, "Attempting to find myself.\n");
        return NULL;
    }

    for(i = 0; i < numneighs; i++) {
        if(neighs[i].interface == interface &&
           id_eq(neighs[i].id, id) && neighs[i].eid == eid) {
            if(create &&
               memcmp(&neighs[i].addr,
                      &create->sin6_addr, sizeof(create->sin6_addr)) != 0 &&
               neighs[i].port == ntohs(create->sin6_port)) {
                debugf("Neighbour changed address.\n");
                memcpy(&neighs[i].addr, create, sizeof(*create));
                neighs[i].port = ntohs(create->sin6_port);
            }
            return &neighs[i];
        }
    }

    if(!create || numneighs >= MAXNEIGHS)
        return NULL;

    memset(&neighs[i], 0, sizeof(struct neighbour));
    neighs[i].interface = interface;
    memcpy(neighs[i].id, id, 4);
    neighs[i].eid = eid;
    memcpy(&neighs[i].addr, &create->sin6_addr, sizeof(create->sin6_addr));
    neighs[i].port = ntohs(create->sin6_port);
    neighs[i].last_contact = now;

    numneighs++;

    republish(1, 1);
    return &neighs[i];
}

void
flush_neighbour(struct neighbour *neigh)
{
    int i = neigh - neighs;

    assert(i >= 0 && i < numneighs);

    if( i < numneighs - 1)
        neighs[i] = neighs[numneighs - 1];
    MEM_UNDEFINED(neighs + numneighs, sizeof(struct neighbour));

    numneighs--;
    republish(1, 1);
}

/* We must maintain the nodes table sorted, see network_hash below. */

struct node *
find_node(const unsigned char *id, int create)
{
    int p = 0;

    if(numnodes > 0) {
        int m, g = numnodes - 1, c;

        do {
            m = (p + g) / 2;
            c = memcmp(id, nodes[m].id, 4);
            if(c == 0)
                return &nodes[m];
            else if(c < 0)
                g = m - 1;
            else
                p = m + 1;
        } while(p <= g);
    }

    if(!create || numnodes >= MAXNODES)
        return NULL;

    if(p < numnodes)
        memmove(nodes + p + 1, nodes + p,
                (numnodes - p) * sizeof(struct node));
    memset(&nodes[p], 0, sizeof(struct node));
    memcpy(nodes[p].id, id, 4);
    numnodes++;

    return &nodes[p];
}

void
flush_node(struct node *node)
{
    int i = node - nodes;
    int j;

    assert(i >= 0 && i < numnodes);

    free(node->neighs);
    free(node->data);
    destroy_prefix_list(node->assigned);
    destroy_prefix_list(node->addresses);
    for(j = 0; j < node->numexts; j++)
        destroy_external(node->exts[j]);
    free(node->exts);

    if(i < numnodes - 1)
        memmove(nodes + i, nodes + i + 1,
                (numnodes - i - 1) * sizeof(struct node));
    MEM_UNDEFINED(nodes + numnodes, sizeof(struct node));

    numnodes--;
}

static int
node_index(const unsigned char *id)
{
    struct node *node = find_node(id, 0);
    if(node) {
        assert(node - nodes >= 0 && node - nodes < numnodes);
        return node - nodes;
    }
    return -1;
}

static int
neigh_symmetric(const struct node *from, const struct node *to,
                const struct node_neighbour *neigh)
{
    int i;
    assert(id_eq(neigh->neigh, to->id));
    for(i = 0; i < to->numneighs; i++) {
        struct node_neighbour *meigh = &to->neighs[i];
        if(id_eq(meigh->neigh, from->id) &&
           meigh->nei == neigh->lei && meigh->lei == neigh->nei)
            return 1;
    }
    return 0;
}

int
silly_walk(struct node *root)
{
    int sp = 0;
    unsigned short stack[numnodes];
    unsigned char seen[numnodes];
    int i, flushed, num;

    memset(seen, 0, sizeof(seen));
    seen[root - nodes] = 1;
    stack[sp++] = root - nodes;

    while(sp > 0) {
        int n = stack[--sp];
        for(i = 0; i < nodes[n].numneighs; i++) {
            struct node_neighbour *neigh = &nodes[n].neighs[i];
            int m = node_index(neigh->neigh);
            if(m < 0) {
                /* Neighbour link to a node we don't know about. */
                continue;
            }
            if(!seen[m] && neigh_symmetric(&nodes[n], &nodes[m], neigh)) {
                assert(sp < numnodes - 1);
                seen[m] = 1;
                stack[sp++] = m;
            }
        }
    }
    /* Flushing a node only moves the nodes *after* the one being flushed.
       Yes, it's a hack. */
    num = numnodes; flushed = 0;
    for(i = numnodes - 1; i >= 0; i--) {
        if(!seen[i]) {
            flush_node(&nodes[i]);
            flushed++;
        }
    }
    debugf("Silly walk flushed %d/%d nodes.\n", flushed, num);
    return !!flushed;
}

int
republish(int do_neighs, int reset)
{
    int rc;
    unsigned char buf[2000];
    struct node *node = find_node(myid, 0);

    if(do_neighs) {
        int i = 0;
        if(node->neighs) {
            free(node->neighs);
            node->neighs = NULL;
            node->numneighs = 0;
        }
        node->neighs = calloc(numneighs, sizeof(struct node_neighbour));
        if(node->neighs == NULL)
            return -1;
        for(i = 0; i < numneighs; i++) {
            memcpy(node->neighs[i].neigh, neighs[i].id, 4);
            node->neighs[i].lei = neighs[i].interface->ifindex;
            node->neighs[i].nei = neighs[i].eid;
        }
        node->numneighs = numneighs;
    }

    rc = format_my_state(buf, 2000);
    if(rc < 0) {
        fprintf(stderr, "Couldn't format my state.\n");
        return -1;
    }
    if(node->data)
        free(node->data);
    node->data = malloc(rc);
    if(node->data == NULL)
        return -1;
    node->datalen = rc;
    memcpy(node->data, buf, rc);
    node_hash(node->datahash, buf, rc);
    node->seqno++;
    node->orig_time = now;

    if(reset)
        trickle_reset_all();

    return 1;
}

void
node_hash(unsigned char *h, const unsigned char *data, int len)
{
    MD5_CTX ctx;
    unsigned char digest[16];
    MD5Init(&ctx);
    MD5Update(&ctx, data, len);
    MD5Final(digest, &ctx);
    memcpy(h, digest, 8);
}

int
network_hash(unsigned char *h)
{
    MD5_CTX ctx;
    unsigned char digest[16];
    int i;

    /* This relies on the node table being sorted. */

    MD5Init(&ctx);
    for(i = 0; i < numnodes; i++) {
        unsigned char s[4];
        DO_HTONL(s, nodes[i].seqno);
        MD5Update(&ctx, s, 4);
        MD5Update(&ctx, nodes[i].datahash, 8);
    }
    MD5Final(digest, &ctx);
    memcpy(h, digest, 8);
    return 1;
}

void
destroy_external(struct external *e)
{
    destroy_prefix_list(e->delegated);
    destroy_prefix_list(e->dns);
    free(e);
}

struct prefix_list *
all_dns(int v6)
{
    int i, j, k;
    struct prefix_list *pl = create_prefix_list(), *pl2;

    for(i = 0; i < numnodes; i++) {
        for(j = 0; j < nodes[i].numexts; j++) {
            if(nodes[i].exts[j]->dns == NULL)
                continue;
            for(k = 0; k < nodes[i].exts[j]->dns->numprefixes; k++) {
                struct prefix *p = &nodes[i].exts[j]->dns->prefixes[k];
                if(!prefix_v4(p) != !!v6)
                    continue;
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
