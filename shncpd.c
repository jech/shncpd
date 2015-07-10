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
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#define __USE_GNU
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "shncpd.h"
#include "trickle.h"
#include "state.h"
#include "send.h"
#include "receive.h"
#include "prefix.h"
#include "util.h"

#define RECVBUF_SIZE 4000
struct timespec now;
const struct timeval zero = {0, 0};

static volatile sig_atomic_t exiting = 0, dumping = 0, changed = 0;
struct in6_addr protocol_group;
unsigned int protocol_port = 8808;
int protocol_socket;

unsigned char myid[4];

struct timespec check_time = {0, 0};
struct timespec prefix_assignment_time = {0, 0};

int debug_level = 0;

int
hn_socket(int port)
{
    struct sockaddr_in6 sin6;
    int s, rc;
    int saved_errno;
    int one = 1, zero = 0;

    s = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if(rc < 0)
        perror("setsockopt(SO_REUSEADDR)");

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                    &zero, sizeof(zero));
    if(rc < 0)
        perror("setsockopt(IPV6_MULTICAST_LOOP)");

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                    &one, sizeof(one));
    if(rc < 0)
        perror("setsockopt(IPV6_MULTICAST_HOPS)");

#ifdef IPV6_V6ONLY
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
                    &one, sizeof(one));
    if(rc < 0)
        perror("setsockopt(IPV6_V6ONLY)");
#endif

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO,  &one, sizeof(one));
    if(rc < 0) {
        perror("setsockopt(IPV6_RECVPKTINFO)");
        goto fail;
    }

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

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    rc = bind(s, (struct sockaddr*)&sin6, sizeof(sin6));
    if(rc < 0)
        goto fail;

    return s;

 fail:
    saved_errno = errno;
    close(s);
    errno = saved_errno;
    return -1;
}

static void
sigexit(int signo)
{
    exiting = 1;
}

static void
sigdump(int signo)
{
    dumping = 1;
}

static void
sigchanged(int signo)
{
    changed = 1;
}

static void
init_signals(void)
{
    struct sigaction sa;
    sigset_t ss;

    sigemptyset(&ss);
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGHUP, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigdump;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigchanged;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGUSR2, &sa, NULL);

#ifdef SIGINFO
    sigemptyset(&ss);
    sa.sa_handler = sigdump;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGINFO, &sa, NULL);
#endif
}

static int
check_interface(struct interface *iif)
{
    int ifindex, rc;
    struct ipv6_mreq mreq;

    ifindex = if_nametoindex(iif->ifname);
    if(ifindex != iif->ifindex) {
        iif->ifindex = ifindex;
        if(iif->ifindex > 0) {
            memset(&mreq, 0, sizeof(mreq));
            memcpy(&mreq.ipv6mr_multiaddr, &protocol_group, 16);
            mreq.ipv6mr_interface = iif->ifindex;
            rc = setsockopt(protocol_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                            (char*)&mreq, sizeof(mreq));
            if(rc < 0) {
                perror("setsockopt(IPV6_JOIN_GROUP)");
                iif->ifindex = 0;
                goto fail;
            }
            return 1;
        }
    }
 fail:
    return 0;
}

static void
check_neighs()
{
    int i = 0;
    int flushed = 0;
    while(i < numneighs) {
        unsigned interval =
            neighs[i].keepalive_interval ?
            neighs[i].keepalive_interval : DNCP_KEEPALIVE_INTERVAL;
        interval = interval * DNCP_KEEPALIVE_MULTIPLIER_PERCENT / 100;
        if(ts_minus_msec(&now, &neighs[i].last_contact) > interval) {
            debugf("Flushing neighbour %s due to inactivity.\n",
                   format_32(neighs[i].id));
            flush_neighbour(&neighs[i]);
            flushed++;
        } else {
            i++;
        }
    }
    if(flushed) {
        silly_walk(find_node(myid, 0));
        prefix_assignment(1, NULL);
        republish(1, 0);
    }
    return;
}

int
main(int argc, char **argv)
{
    char *group = "ff02::8808";
    int opt, rc, i;
    unsigned int seed;
    struct node *node;
    unsigned char *recvbuf = NULL;

    while(1) {
        opt = getopt(argc, argv, "m:p:d:");
        if(opt < 0)
            break;

        switch(opt) {
        case 'm':
            group = optarg;
            break;
        case 'p':
            protocol_port = atoi(optarg);
            if(protocol_port <= 0 || protocol_port > 0xFFFF)
                goto usage;
            break;
        case 'd':
            debug_level = atoi(optarg);
            break;
        default:
            goto usage;
        }
    }

    if(optind >= argc)
        goto usage;

    for(i = optind; i < argc; i++) {
        if(i - optind >= MAXINTERFACES) {
            fprintf(stderr, "Too many interfaces.\n");
            exit(1);
        }
        interfaces[i - optind].ifname = argv[i];
    }
    numinterfaces = i - optind;

    rc = inet_pton(AF_INET6, group, &protocol_group);
    if(rc <= 0)
        goto usage;

    gettime(&now);

    read_random_bytes(&seed, sizeof(seed));
    seed ^= now.tv_nsec;
    srandom(seed);

    rc = read_random_bytes(myid, sizeof(myid));
    if(rc != sizeof(myid)) {
        perror("get_random_bytes");
        exit(1);
    }

    node = find_node(myid, 1);
    if(node == NULL) {
        fprintf(stderr, "Couldn't create myself.\n");
        exit(1);
    }

    rc = republish(1, 0);
    if(rc < 0) {
        fprintf(stderr, "Couldn't compute myself.\n");
        goto fail;
    }

    recvbuf = allocate_buffer(RECVBUF_SIZE);
    if(recvbuf == NULL) {
        perror("Couldn't allocate receive buffer.\n");
        exit(1);
        goto fail;
    }

    protocol_socket = hn_socket(protocol_port);
    if(protocol_socket < 0) {
        perror("hn_socket");
        goto fail;
    }

    for(i = 0; i < numinterfaces; i++) {
        trickle_init(&interfaces[i].trickle, HNCP_I_min, HNCP_I_max, 1);
        check_interface(&interfaces[i]);
        if(interfaces[i].ifindex <= 0) {
            fprintf(stderr, "Warning: unknown interface %s.\n",
                    interfaces[i].ifname);
            continue;
        }
        ts_add_random(&check_time, &now, 20000);
    }

    ts_add_random(&prefix_assignment_time, &now, 5000);

    init_signals();

    debugf("My id: %s\n", format_32(myid));

    while(1) {
        fd_set readfds;
        struct timespec ts;

        ts = check_time;
        ts_min(&ts, &prefix_assignment_time);

        for(i = 0; i < numinterfaces; i++) {
            struct timespec t;
            struct timespec k;
            trickle_deadline(&t, &interfaces[i].trickle);
            ts_min(&ts, &t);
            ts_add_msec(&k, &interfaces[i].last_sent,
                        DNCP_KEEPALIVE_INTERVAL);
            ts_add_random(&k, &k, HNCP_I_min / 2);
            ts_min(&ts, &k);
        }

        FD_ZERO(&readfds);

        gettime(&now);

        if(ts_compare(&ts, &now) > 0) {
            ts_minus(&ts, &ts, &now);

            FD_SET(protocol_socket, &readfds);
            rc = pselect(protocol_socket + 1, &readfds, NULL, NULL, &ts, NULL);
            if(rc < 0 && errno != EINTR) {
                perror("select");
                sleep(1);
                continue;
            }
            gettime(&now);
        }

        if(exiting)
            break;

        if(dumping) {
            int i;
            for(i = 0; i < numinterfaces; i++) {
                printf("Interface %s\n", interfaces[i].ifname);
            }
            for(i = 0; i < numneighs; i++)
                printf("Neighbour %s %s last_contact %dms\n",
                       format_32(neighs[i].id), neighs[i].interface->ifname,
                       ts_minus_msec(&now, &neighs[i].last_contact));
            for(i = 0; i < numnodes; i++)
                printf("Node %s hash %s length %d\n",
                       format_32(nodes[i].id),
                       format_64(nodes[i].datahash), nodes[i].datalen);
            fflush(stdout);
            dumping = 0;
        }

        if(changed) {
            for(i = 0; i < numinterfaces; i++)
                check_interface(&interfaces[i]);
            check_neighs();
            ts_add_random(&check_time, &now, 20000);
            changed = 0;
        }

        for(i = 0; i < numinterfaces; i++) {
             if(trickle_trigger(&interfaces[i].trickle)) {
                buffer_network_state(NULL, &interfaces[i]);
                interfaces[i].last_sent = now;
            } else if(ts_minus_msec(&now, &interfaces[i].last_sent) >=
                      DNCP_KEEPALIVE_INTERVAL) {
                trickle_new_t(&interfaces[i].trickle);
                buffer_network_state(NULL, &interfaces[i]);
                interfaces[i].last_sent = now;
            }
        }

        if(ts_compare(&now, &check_time) > 0) {
            for(i = 0; i < numinterfaces; i++)
                check_interface(&interfaces[i]);
            check_neighs();
            ts_add_random(&check_time, &now, 20000);
        }

        if(ts_compare(&now, &prefix_assignment_time) > 0) {
            int r, msecs;
            msecs = prefix_assignment(0, &r);
            ts_add_msec(&prefix_assignment_time, &now, msecs);
            if(r)
                republish(0, 1);
        }

        if(FD_ISSET(protocol_socket, &readfds)) {
            struct sockaddr_in6 sin6;
            int unicast;
            int interface;
            int len;
            struct iovec iov[1];
            struct msghdr msg;
            int cmsglen = 100;
            char cmsgbuf[cmsglen];
            struct cmsghdr *cmsg = (struct cmsghdr*)cmsgbuf;

            iov[0].iov_base = recvbuf;
            iov[0].iov_len = RECVBUF_SIZE;
            memset(&msg, 0, sizeof(msg));
            msg.msg_name = &sin6;
            msg.msg_namelen = sizeof(sin6);
            msg.msg_iov = iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg;
            msg.msg_controllen = cmsglen;

            len = recvmsg(protocol_socket, &msg, 0);
            if(len < 0) {
                if(errno != EAGAIN && errno != EINTR) {
                    perror("recv");
                    sleep(5);
                }
                goto fail2;
            }

            if(msg.msg_namelen < sizeof(struct sockaddr_in6) ||
               sin6.sin6_family != AF_INET6) {
                fprintf(stderr, "Non-v6 packet.\n");
                continue;
            }

            if(IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr)) {
                for(i = 0; i < numinterfaces; i++) {
                    if(interfaces[i].ifindex <= 0)
                        continue;
                    if(interfaces[i].ifindex == sin6.sin6_scope_id)
                        break;
                }
                if(i >= numinterfaces) {
                    fprintf(stderr,
                            "Received packet on unknown interface.\n");
                    goto fail2;
                }
                interface = i;
            } else {
                fprintf(stderr, "Received packet on non-link-local address.\n");
                goto fail2;
            }

            unicast = -1;
            cmsg = CMSG_FIRSTHDR(&msg);
            while(cmsg != NULL) {
                if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
		    (cmsg->cmsg_type == IPV6_PKTINFO)) {
                    struct in6_pktinfo *info = CMSG_DATA(cmsg);
                    unicast = !IN6_IS_ADDR_MULTICAST(&info->ipi6_addr);
                    break;
                }
                cmsg = CMSG_NXTHDR(&msg, cmsg);
            }
            if(unicast < 0) {
                fprintf(stderr, "Couldn't determine source of packet.\n");
                unicast = 0;
            }
            parse_packet(recvbuf, len, &sin6, unicast, &interfaces[interface]);
            MEM_UNDEFINED(recvbuf, RECVBUF_SIZE);
        }
    fail2:
        flushbuf();
    }

    prefix_assignment_cleanup();

    return 0;

 usage:
    fprintf(stderr,
            "shcpd [-m group] [-p port] [-d debug-level] interface...\n");
 fail:
    exit(1);
}
