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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"
#include "kernel.h"

static const unsigned char v4prefix[16] =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };

int
kernel_address(int ifindex, const char *ifname,
               const struct in6_addr *address, int plen,
               int add)
{
    char b[INET6_ADDRSTRLEN];
    char c[INET6_ADDRSTRLEN + 80];
    int rc;

    if(memcmp(address, v4prefix, 12) == 0) {
        inet_ntop(AF_INET, (char*)address + 12, b, sizeof(b));
        plen -= 96;
    } else {
        inet_ntop(AF_INET6, address, b, sizeof(b));
    }

    rc = snprintf(c, sizeof(c), "ip addr %s %s/%d dev %s",
                  add ? "add" : "del", b, plen, ifname);
    if(rc < 1 || rc >= sizeof(c)) {
        errno = ENOSPC;
        return -1;
    }

    rc = system(c);
    if(rc >= 0 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0)
        return 1;

    return -1;
}

int
kernel_apply(int ifindex, const char *ifname,
             const struct in6_addr *prefix, int plen,
             int add)
{
    char b[INET6_ADDRSTRLEN];
    char c[INET6_ADDRSTRLEN + 80];
    int rc;

    if(memcmp(prefix, v4prefix, 12) == 0) {
        inet_ntop(AF_INET, (char*)prefix + 12, b, sizeof(b));
        plen -= 96;
    } else {
        inet_ntop(AF_INET6, prefix, b, sizeof(b));
    }

    rc = snprintf(c, sizeof(c), "ip route %s %s/%d dev %s proto 43",
                  add ? "add" : "del", b, plen, ifname);
    if(rc < 1 || rc >= sizeof(c)) {
        errno = ENOSPC;
        return -1;
    }

    rc = system(c);
    if(rc >= 0 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0)
        return 1;

    return -1;
}

int
kernel_router()
{
    char buf[100];
    int fd, rc;

    fd = open("/proc/sys/net/ipv6/conf/all/forwarding", O_RDONLY);
    if(fd < 0)
        return -1;

    rc = read(fd, buf, 99);
    if(rc < 0) {
        close(fd);
        return -1;
    }
    close(fd);

    buf[rc] = '\0';

    return atoi(buf);
}
