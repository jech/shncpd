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

#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>
#include <sys/mman.h>
#include "shncpd.h"
#include "util.h"

int
read_random_bytes(void *buf, int len)
{
    int fd, rc;

    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        errno = ENOSYS;
        return -1;
    }

    rc = read(fd, buf, len);
    if(rc < len)
        rc = -1;

    close(fd);

    return rc;
}

int
gettime(struct timespec *ts)
{
    return clock_gettime(CLOCK_MONOTONIC, ts);
}

int
ts_compare(const struct timespec *s1, const struct timespec *s2)
{
    if(s1->tv_sec < s2->tv_sec)
        return -1;
    else if(s1->tv_sec > s2->tv_sec)
        return 1;
    else if(s1->tv_nsec < s2->tv_nsec)
        return -1;
    else if(s1->tv_nsec > s2->tv_nsec)
        return 1;
    else
        return 0;
}

/* {0, 0} represents infinity */
void
ts_min(struct timespec *d, const struct timespec *s)
{
    if(s->tv_sec == 0)
        return;

    if(d->tv_sec == 0 || ts_compare(d, s) > 0) {
        *d = *s;
    }
}

void
ts_minus(struct timespec *d,
         const struct timespec *s1, const struct timespec *s2)
{
    if(s1->tv_nsec >= s2->tv_nsec) {
        d->tv_nsec = s1->tv_nsec - s2->tv_nsec;
        d->tv_sec = s1->tv_sec - s2->tv_sec;
    } else {
        d->tv_nsec = s1->tv_nsec + 1000000000 - s2->tv_nsec;
        d->tv_sec = s1->tv_sec - s2->tv_sec - 1;
    }
}

int
ts_minus_msec(const struct timespec *s1, const struct timespec *s2)
{
    return (s1->tv_sec - s2->tv_sec) * 1000 +
        (s1->tv_nsec - s2->tv_nsec) / 1000000;
}

static void
ts_add_nsec(struct timespec *d, const struct timespec *s, long long nsecs)
{
    *d = *s;

    while(nsecs + d->tv_nsec > 1000000000) {
        d->tv_sec += 1;
        nsecs -= 1000000000LL;
    }

    while(nsecs + d->tv_nsec < 0) {
        d->tv_sec -= 1;
        nsecs += 1000000000LL;
    }

    d->tv_nsec += nsecs;
}

static const long long million = 1000000LL;

void
ts_add_msec(struct timespec *d, const struct timespec *s, int msecs)
{
    ts_add_nsec(d, s, msecs * million);
}

void
ts_add_random(struct timespec *d, const struct timespec *s, int msecs)
{
    ts_add_nsec(d, s, (random() % msecs) * million + random() % million);
}

const char *
format_32(const unsigned char *data)
{
    static char buf[4][16];
    static int i = 0;
    i = (i + 1) % 4;
    snprintf(buf[i], 16, "%02x:%02x:%02x:%02x",
             data[0], data[1], data[2], data[3]);
    return buf[i];
}

const char *
format_64(const unsigned char *data)
{
    static char buf[4][28];
    static int i = 0;
    i = (i + 1) % 4;
    snprintf(buf[i], 28, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             data[0], data[1], data[2], data[3],
             data[4], data[5], data[6], data[7]);
    return buf[i];
}

void
do_debugf(int level, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if(debug_level >= level) {
        vfprintf(stderr, format, args);
        fflush(stderr);
    }
    va_end(args);
}

void *
allocate_buffer(int size)
{
    void *p;
    p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);
    if(p == MAP_FAILED)
        return NULL;
    return p;
}
