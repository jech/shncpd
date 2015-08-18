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

#define BACKOFF_MAX_DELAY 4000
#define FLOODING_DELAY 5000

struct prefix {
    struct in6_addr p;
    unsigned char plen;
    unsigned short prio;
    unsigned char id[4];
    unsigned int eid;
};

struct prefix_list {
    struct prefix *prefixes;
    short numprefixes;
    short maxprefixes;
};

struct assigned_prefix {
    struct prefix delegated;
    struct prefix assigned;
    int published;
    int applied;
    struct timespec backoff_timer, apply_timer;
    struct in6_addr assigned_address;
};

struct interface;
struct external;

void debug_address(const struct in6_addr *a);
void debug_prefix(const struct prefix *p);
void debug_prefix_list(const struct prefix_list *pl);
int parse_prefix(const char *string, struct prefix *p);
struct prefix_list *create_prefix_list(void);
void destroy_prefix_list(struct prefix_list *pl);
struct prefix_list *
prefix_list_cons_prefix(struct prefix_list *pl, const struct prefix *p);
struct prefix_list * prefix_list_cons(struct prefix_list *pl,
                                      const struct in6_addr *a, int plen,
                                      const unsigned char *id,
                                      unsigned int eid, int prio);
int prefix_list_member(const struct prefix *p, const struct prefix_list *pl);
int prefix_within(const struct prefix *p, const struct prefix *q);
int prefix_within_v4(const unsigned char *p4, const struct prefix *q);
int prefix_list_within(const struct prefix *p, const struct prefix_list *pl);
int prefix_list_within_v4(const unsigned char *p4,
                          const struct prefix_list *pl);
int prefix_v4(struct prefix *p);
int interface_v4(struct interface *interface, unsigned char *v4_return);
int generate_random_v4(unsigned char *ip, const struct prefix_list *pl);
int route_externals(struct external **ext, int numexternals, int add);
int prefix_assignment(int changed);
void prefix_assignment_cleanup();
