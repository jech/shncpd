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

#define MAXINTERFACES 20
#define MAXNODES 100
#define MAXNEIGHS 40

struct interface {
    char *ifname;
    int ifindex;
    struct timespec last_request_sent;
    struct timespec last_sent;
    struct trickle_state trickle;
    /* Prefix assignment */
    struct assigned_prefix *assigned;
    int numassigned;
    /* Router advertisements */
    struct timespec ra_timeout;
    struct timespec last_ra_sent;
    struct prefix_list *retractions;
};

struct node {
    struct interface *interface;
    unsigned char id[4];
    unsigned char *data;
    unsigned int datalen;
    unsigned char datahash[8];
    unsigned int seqno;
    struct timespec orig_time;
    /* From published node state */
    unsigned char capabilities[2];
    struct node_neighbour *neighs;
    int numneighs;
    struct prefix_list *assigned;
    struct prefix_list *addresses;
    struct external **exts;
    int numexts;
};

struct neighbour {
    struct interface *interface;
    unsigned char id[4];
    unsigned int eid;
    unsigned short port;
    struct in6_addr addr;
    struct timespec last_contact;
    unsigned keepalive_interval;
};

struct node_neighbour {
    unsigned char neigh[4];
    unsigned int nei;
    unsigned int lei;
};

struct external {
    struct prefix_list *delegated;
    struct prefix_list *dns;
};

extern struct interface interfaces[MAXINTERFACES];
extern int numinterfaces;

extern struct node nodes[MAXNODES];
extern int numnodes;

extern struct neighbour neighs[MAXNEIGHS];
extern int numneighs;

static inline int
id_eq(const unsigned char *id1, const unsigned char *id2)
{
    return memcmp(id1, id2, 4) == 0;
}

void trickle_reset_all(void);
struct interface *find_interface(int ifindex);
struct neighbour *
find_neighbour(struct interface *interface, const unsigned char *id,
               unsigned int eid, const struct sockaddr_in6 *create);
void flush_neighbour(struct neighbour *neighbour);
struct node *find_node(const unsigned char *id, int create);
void flush_node(struct node *node);
int silly_walk(struct node *root);
int republish(int do_neighs, int reset);
void node_hash(unsigned char *h, const unsigned char *data, int len);
int network_hash(unsigned char *);
void destroy_external(struct external *e);
struct prefix_list *all_dns(int v6);
