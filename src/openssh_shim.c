#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include "third-party/openssh/sshkey.h"

/* Stub DNS host key verification: DNS SSHFP lookups disabled in this build. */
int verify_host_key_dns(const char *hostname, struct sockaddr *address,
                        struct sshkey *hostkey, int *flags) {
    (void)hostname;
    (void)address;
    (void)hostkey;
    if (flags) {
        *flags = 0;
    }
    return -1; /* act as if no DNS data was found */
}

/* Stub SSHFP zone-record export (ssh-keygen -r): dns.c is excluded from this
 * build along with DNS SSHFP support in general, so this rarely-used
 * ssh-keygen flag is unavailable rather than silently producing wrong
 * output. */
int export_dns_rr(const char *hostname, struct sshkey *key, FILE *f,
                  int generic, int hash_type) {
    (void)hostname;
    (void)key;
    (void)f;
    (void)generic;
    (void)hash_type;
    fprintf(stderr, "ssh-keygen: DNS SSHFP record export is unavailable in this build\n");
    return -1;
}
