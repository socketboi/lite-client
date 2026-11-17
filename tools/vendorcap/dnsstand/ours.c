/* lite-client's lookup, printed the way ref/main.go prints the reference's: src/net/goresolve.c over
 * the machine's own /etc/resolv.conf, /etc/nsswitch.conf and /etc/hosts. */
#include "net/goresolve.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    lc_goaddrs l;
    char       why[256];
    if (lc_go_lookup_ip(argv[1], -1, &l, why, sizeof why) != 0) {
        printf("ERR %s\n", why);
        return 0;
    }
    printf("ADDRS");
    if (l.n == 0u)
        printf(" "); /* Println("ADDRS", "") */
    for (unsigned i = 0; i < l.n; i++) {
        char s[INET6_ADDRSTRLEN];
        if (l.a[i].v4)
            inet_ntop(AF_INET, l.a[i].ip + 12, s, sizeof s);
        else
            inet_ntop(AF_INET6, l.a[i].ip, s, sizeof s);
        printf(" %s%s%s", s, l.a[i].zone[0] != '\0' ? "%" : "", l.a[i].zone);
    }
    printf("\n");
    lc_goaddrs_free(&l);
    return 0;
}
