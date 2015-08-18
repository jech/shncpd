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


int parse_packet(const unsigned char *buf, int buflen,
                 struct sockaddr_in6 *sin6, int unicast,
                 struct interface *interface);
int parse_node_state(struct node *node);
struct external *
parse_external(struct node *node, const unsigned char *buf, int buflen);
int parse_dhcpv4(const unsigned char *buf, int buflen,
                 struct prefix_list **dns, struct prefix_list **ntp);
int parse_dhcpv6(const unsigned char *buf, int buflen,
                 struct prefix_list **dns, struct prefix_list **ntp);
