#!/bin/sh

if [ "$HNCP_DEBUG_LEVEL" -ge 2 ]; then
   set | grep '^HNCP_'
fi

if [ "$HNCP_DEBUG_LEVEL" -ge 3 ]; then
   set -x
fi

dns_add() {
    if [ -x /sbin/resolvconf ]; then
        /sbin/resolvconf -a lo.shncpd
    else
        mv /etc/resolv.conf /etc/resolv.conf.orig
        cat > /etc/resolv.conf
    fi
}

dns_remove() {
    if [ -x /sbin/resolvconf ]; then
        /sbin/resolvconf -d lo.shncpd
    else
        mv /etc/resolv.conf.org /etc/resolv.conf
    fi
}


case "$1" in
    up)
        if [ -n "$HNCP_IPv4_NAMESERVERS" ] ||
           [ -n "$HNCP_IPv6_NAMESERVERS" ]; then
            (for i in $HNCP_IPv4_NAMESERVERS $HNCP_IPv6_NAMESERVERS; do
                 echo "nameserver $i"
             done) | resolvconf -a lo.shncpd
        fi
        ;;
    down)
        resolvconf -d lo.shncpd
        ;;
esac


