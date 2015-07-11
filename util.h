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


#ifdef NO_DEBUG
#define debugf(...) do {} while(0)
#else
extern int debug_level;
#define debugf(...) \
    do { \
        if(debug_level >= 2) do_debugf(2, __VA_ARGS__); \
    } while(0)
#endif

#define DO_NTOHS(_d, _s) \
    do { unsigned short _dd; \
         memcpy(&(_dd), (_s), 2); \
         _d = ntohs(_dd); } while(0)
#define DO_NTOHL(_d, _s) \
    do { unsigned int _dd; \
         memcpy(&(_dd), (_s), 4); \
         _d = ntohl(_dd); } while(0)
#define DO_HTONS(_d, _s) \
    do { unsigned short _dd; \
         _dd = htons(_s); \
         memcpy((_d), &(_dd), 2); } while(0)
#define DO_HTONL(_d, _s) \
    do { unsigned _dd; \
         _dd = htonl(_s); \
         memcpy((_d), &(_dd), 4); } while(0)

#ifdef HAVE_VALGRIND
#include <valgrind/memcheck.h>
#define MEM_UNDEFINED VALGRIND_MAKE_MEM_UNDEFINED
#else
#define MEM_UNDEFINED(_a, _l) do {} while(0)
#endif

static inline int
min(int x, int y)
{
    return x > y ? y : x;
}

static inline int
max(int x, int y)
{
    return x > y ? x : y;
}

int read_random_bytes(void *buf, int len);
int gettime(struct timespec *ts);
int ts_compare(const struct timespec *s1, const struct timespec *s2);
void ts_min(struct timespec *d, const struct timespec *s);
void ts_minus(struct timespec *d,
              const struct timespec *s1, const struct timespec *s2);
int ts_minus_msec(const struct timespec *s1, const struct timespec *s2);
void ts_min_sec(struct timespec *d, int secs);
void ts_add_msec(struct timespec *d, const struct timespec *s, int msecs);
void ts_add_random(struct timespec *d, const struct timespec *s, int msecs);
void ts_zero(struct timespec *d);
const char *format_32(const unsigned char *data);
const char *format_64(const unsigned char *data);
void do_debugf(int level, const char *format, ...)
#ifdef __GNUC__
    __attribute__((format (printf, 2, 3))) __attribute__((cold))
#endif
;
void *allocate_buffer(int size);
