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
#include <stdlib.h>

#include "shncpd.h"
#include "trickle.h"
#include "util.h"

void
trickle_init(struct trickle_state *s, int I_min, int I_max, int k)
{
    memset(s, 0, sizeof(*s));
    s->I_min = I_min;
    s->I_max = I_max;
    s->k = k;

    s->I = I_min + (random() % (I_max - I_min));
    trickle_new_interval(s);
}

void
trickle_new_t(struct trickle_state *s)
{
    s->t = s->I / 2 + (random() % (s->I / 2));
}

void
trickle_new_interval(struct trickle_state *s)
{
    s->c = 0;
    trickle_new_t(s);
    s->I_start = now;
    s->triggered = 0;
}

void
trickle_deadline(struct timespec *deadline, const struct trickle_state *s)
{
    int d = s->triggered ? s->I : s->t;
    ts_add_msec(deadline, &s->I_start, d);
}

int
trickle_trigger(struct trickle_state *s)
{
    if(!s->triggered) {
        struct timespec tt;
        ts_add_msec(&tt, &s->I_start, s->t);
        if(ts_compare(&now, &tt) >= 0) {
            s->triggered = 1;
            return s->c < s->k;
        }
    } else {
        struct timespec tI;
        ts_add_msec(&tI, &s->I_start, s->I);
        if(ts_compare(&now, &tI) >= 0) {
            s->I = min(2 * s->I, s->I_max);
            trickle_new_interval(s);
        }
    }
    return 0;
}

void
trickle_reset(struct trickle_state *s, int consistent)
{
    if(consistent) {
        s->c++;
    } else if(s->I > s->I_min) {
        s->I = s->I_min;
        trickle_new_interval(s);
    }
}


