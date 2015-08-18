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
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "trickle.h"
#include "state.h"
#include "prefix.h"
#include "util.h"
#include "local.h"

char *local_script = NULL;

static int
set_config_var(const char *name, const struct prefix_list *pl, int v4)
{
    char buf[(INET6_ADDRSTRLEN + 1) * 20 ];

    if(pl && pl->prefixes > 0) {
        int i;
        buf[0] = '\0';
        for(i = 0; i < pl->numprefixes; i++) {
            char a[INET6_ADDRSTRLEN];
            if(v4)
                inet_ntop(AF_INET, (unsigned char*)&pl->prefixes[i].p + 12,
                          a, sizeof(a));
            else
                inet_ntop(AF_INET6, &pl->prefixes[i].p, a, sizeof(a));
            if(i > 0)
                strncat(buf, " ", sizeof(buf));
            strncat(buf, a, sizeof(buf));
        }
        return setenv(name, buf, 1);
    }
    return 0;
}

int
run_local_script(int up)
{
    pid_t pid;
    if(local_script == NULL || local_script[0] == '\0')
        return 0;

    debugf("Calling local configuration script (%d).\n", up);

    pid = fork();
    if(pid < 0)
        return pid;

    if(pid == 0) {
        char buf[20];
        snprintf(buf, 20, "%d", debug_level);
        setenv("HNCP_DEBUG_LEVEL", buf, 1);
        if(up) {
            struct prefix_list *pl;
            pl = all_dhcp_data(0, 1, 0);
            set_config_var("HNCP_IPv4_NAMESERVERS", pl, 1);
            destroy_prefix_list(pl);
            pl = all_dhcp_data(0, 0, 1);
            set_config_var("HNCP_IPv6_NAMESERVERS", pl, 0);
            destroy_prefix_list(pl);
            pl = all_dhcp_data(1, 1, 0);
            set_config_var("HNCP_IPv4_NTP_SERVERS", pl, 1);
            destroy_prefix_list(pl);
            pl = all_dhcp_data(1, 0, 1);
            set_config_var("HNCP_IPv6_NTP_SERVERS", pl, 0);
            destroy_prefix_list(pl);
        }
        execl(local_script, local_script, up ? "up" : "down" , NULL);
        perror("exec(local_script)");
        exit(42);
    } else {
        int status;
    again:
        pid = waitpid(pid, &status, 0);
        if(pid < 0) {
            if(errno == EINTR)
                goto again;
            perror("wait");
            return -1;
        } else if(!WIFEXITED(status)) {
            fprintf(stderr, "Configuration script died violently (%d)\n",
                    status);
            return 0;
        } else if(WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Configuration script erred out %d\n",
                    WEXITSTATUS(status));
            return 0;
        }
        return 1;
    }
}
