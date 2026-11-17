/* The chain check a REALITY client makes when the node did not authenticate it.
 *
 * This is the difference between "the node does not know us" and "somebody is standing in the
 * middle", and until src/cert/chain.c existed there was none: both ended in a completed handshake
 * against a certificate nobody looked at. The reference makes the difference with Go's x509 against
 * the machine's root store (vendor/Xray-core/transport/internet/reality/reality.go:129-139), and a
 * failure there ends the handshake with bad_certificate rather than reaching the spider.
 *
 * So what has to be tested is not "does mbedTLS verify certificates" — it does — but that the four
 * ways this can go wrong are told apart, and that the store the answer depends on is the one the
 * reference would have used. The fixtures come from Go's own x509, and the trusted root is a file
 * this test writes and points SSL_CERT_FILE at, so the store under test is known rather than
 * whatever the build machine happens to trust.
 *
 * The last case is the one worth having: a system with NO certificate authorities refuses, rather
 * than deciding that an unverifiable certificate is fine because there was nothing to check it
 * against. */

#include "cert/chain.h"
#include "cert/cert.h"
#include "chain_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

static void ok(const char *what) { printf("  ok    %s\n", what); }

static void fail(const char *what, const char *why)
{
    printf("  FAIL  %s%s%s\n", what, why != NULL ? ": " : "", why != NULL ? why : "");
    failures++;
}

/* A TLS 1.3 Certificate message body: an empty request context, then the list, each entry followed
 * by its own (empty) extensions block. Built here rather than captured because what the test needs
 * to vary is which certificates are in it and in what order. */
typedef struct {
    const uint8_t *der;
    size_t         len;
} entry;

static size_t build(uint8_t *out, size_t cap, const entry *entries, size_t count)
{
    size_t list = 0;
    for (size_t i = 0; i < count; i++)
        list += 3u + entries[i].len + 2u;

    size_t need = 1u + 3u + list;
    if (need > cap) {
        fprintf(stderr, "the message does not fit the buffer\n");
        exit(2);
    }

    size_t off = 0;
    out[off++] = 0x00u; /* certificate_request_context, empty */
    out[off++] = (uint8_t)(list >> 16);
    out[off++] = (uint8_t)(list >> 8);
    out[off++] = (uint8_t)list;
    for (size_t i = 0; i < count; i++) {
        out[off++] = (uint8_t)(entries[i].len >> 16);
        out[off++] = (uint8_t)(entries[i].len >> 8);
        out[off++] = (uint8_t)entries[i].len;
        memcpy(out + off, entries[i].der, entries[i].len);
        off += entries[i].len;
        out[off++] = 0x00u; /* extensions, empty */
        out[off++] = 0x00u;
    }
    return off;
}

static uint8_t msg[8192];

static void must_pass(const char *what, const entry *entries, size_t count, const char *host)
{
    size_t len = build(msg, sizeof msg, entries, count);
    char   why[192] = { 0 };
    if (lc_chain_verify(msg, len, host, why, sizeof why) == 0)
        ok(what);
    else
        fail(what, why);
}

static void must_refuse(const char *what, const entry *entries, size_t count, const char *host)
{
    size_t len = build(msg, sizeof msg, entries, count);
    char   why[192] = { 0 };
    if (lc_chain_verify(msg, len, host, why, sizeof why) != 0)
        printf("  ok    %s (%s)\n", what, why);
    else
        fail(what, "it was accepted");
}

/* Writes the one root this test trusts, and points the loader at it exactly as an operator would.
 * SSL_CERT_FILE is not a testing hook: Go's system pool reads it first, so this is the reference's
 * own way of saying which store to use. */
static char root_path[] = "/tmp/lc-chain-root-XXXXXX";

static void write_root(void)
{
    int fd = mkstemp(root_path);
    if (fd < 0) {
        perror("mkstemp");
        exit(2);
    }
    size_t off = 0;
    while (off < sizeof chain_root_pem) {
        ssize_t n = write(fd, chain_root_pem + off, sizeof chain_root_pem - off);
        if (n <= 0) {
            perror("write");
            exit(2);
        }
        off += (size_t)n;
    }
    close(fd);
    setenv("SSL_CERT_FILE", root_path, 1);
    /* So that a machine with a real /etc/ssl/certs cannot quietly supply what the file did not:
     * both halves of the search have to be under the test's control for its answers to mean
     * anything. */
    setenv("SSL_CERT_DIR", "/nonexistent", 1);
}

int main(void)
{
    printf("chain verification, the REALITY stranger path\n\n");
    write_root();

    const entry leaf = { chain_leaf_der, sizeof chain_leaf_der };
    const entry inter = { chain_inter_der, sizeof chain_inter_der };
    const entry expired = { chain_expired_der, sizeof chain_expired_der };
    const entry stranger = { chain_stranger_der, sizeof chain_stranger_der };

    /* ---- the case that must work: a real masquerade ---- */
    {
        const entry full[] = { leaf, inter };
        must_pass("leaf and intermediate reach the trusted root", full, 2, "www.example.com");
    }

    /* ---- the four ways it goes wrong ---- */
    {
        const entry full[] = { leaf, inter };
        /* The name is the half of this check that an attacker with ANY valid certificate would
         * otherwise walk through. */
        must_refuse("a valid chain for the wrong name", full, 2, "www.kinopoisk.ru");

        const entry orphan[] = { leaf };
        must_refuse("a leaf with no path to a root", orphan, 1, "www.example.com");

        const entry stale[] = { expired, inter };
        must_refuse("an expired leaf", stale, 2, "www.example.com");

        const entry alone[] = { stranger };
        must_refuse("a self-signed certificate with the right name", alone, 1, "www.example.com");
    }

    /* ---- malformed input, which arrives before anything is authenticated ---- */
    {
        char why[192];

        static const uint8_t empty_list[] = { 0x00, 0x00, 0x00, 0x00 };
        if (lc_chain_verify(empty_list, sizeof empty_list, "www.example.com", why, sizeof why) != 0)
            ok("an empty certificate list is refused");
        else
            fail("an empty certificate list was accepted", NULL);

        const entry full[] = { leaf, inter };
        size_t      len = build(msg, sizeof msg, full, 2);
        if (lc_chain_verify(msg, len - 20u, "www.example.com", why, sizeof why) != 0)
            ok("a truncated certificate list is refused");
        else
            fail("a truncated certificate list was accepted", NULL);

        /* One byte inside the leaf's signature. The list still walks; the path no longer builds. */
        len = build(msg, sizeof msg, full, 2);
        msg[4u + 3u + sizeof chain_leaf_der - 1u] ^= 0xffu;
        if (lc_chain_verify(msg, len, "www.example.com", why, sizeof why) != 0)
            ok("a leaf whose signature was altered is refused");
        else
            fail("an altered leaf was accepted", NULL);
    }

    /* ---- the walk itself, which the verifier depends on and nothing else exercised ---- */
    {
        const entry full[] = { leaf, inter };
        size_t      len = build(msg, sizeof msg, full, 2);

        size_t         off = 0;
        const uint8_t *der = NULL;
        size_t         der_len = 0;
        int            first = lc_cert_next_from_message(msg, len, &off, &der, &der_len);
        int            leaf_right = first == 0 && der_len == sizeof chain_leaf_der &&
                         memcmp(der, chain_leaf_der, der_len) == 0;
        int second = lc_cert_next_from_message(msg, len, &off, &der, &der_len);
        int inter_right = second == 0 && der_len == sizeof chain_inter_der &&
                          memcmp(der, chain_inter_der, der_len) == 0;
        int end = lc_cert_next_from_message(msg, len, &off, &der, &der_len);

        if (leaf_right && inter_right && end == 1)
            ok("the certificate list walks leaf first, then the intermediate, then ends");
        else
            fail("the certificate list does not walk in order", NULL);

        /* The one the old walk would have got wrong: an entry whose extensions are not empty. The
         * next length is on the other side of them. */
        uint8_t with_ext[8192];
        size_t  n = 0;
        with_ext[n++] = 0x00u;
        size_t list = (3u + sizeof chain_leaf_der + 2u + 4u) + (3u + sizeof chain_inter_der + 2u);
        with_ext[n++] = (uint8_t)(list >> 16);
        with_ext[n++] = (uint8_t)(list >> 8);
        with_ext[n++] = (uint8_t)list;
        with_ext[n++] = (uint8_t)(sizeof chain_leaf_der >> 16);
        with_ext[n++] = (uint8_t)(sizeof chain_leaf_der >> 8);
        with_ext[n++] = (uint8_t)sizeof chain_leaf_der;
        memcpy(with_ext + n, chain_leaf_der, sizeof chain_leaf_der);
        n += sizeof chain_leaf_der;
        /* Four bytes of extensions: one empty extension of a type the reference does not know.
         *
         * It used to be 0x0005 — status_request — and that was the bug this fixture pinned rather
         * than caught. An empty status_request is refused by every Go client on the first read
         * (`extData.ReadUint8(&statusType)` on nothing, utls/handshake_messages.go:1626-1631), so the
         * assertion said "stepped over" about a message the reference stops on. The claim the test
         * means to make is about UNKNOWN extensions, which really are skipped whole
         * (:1644-1646), so it now uses one. */
        with_ext[n++] = 0x00u;
        with_ext[n++] = 0x04u;
        with_ext[n++] = 0xffu;
        with_ext[n++] = 0xa5u;
        with_ext[n++] = 0x00u;
        with_ext[n++] = 0x00u;
        with_ext[n++] = (uint8_t)(sizeof chain_inter_der >> 16);
        with_ext[n++] = (uint8_t)(sizeof chain_inter_der >> 8);
        with_ext[n++] = (uint8_t)sizeof chain_inter_der;
        memcpy(with_ext + n, chain_inter_der, sizeof chain_inter_der);
        n += sizeof chain_inter_der;
        with_ext[n++] = 0x00u;
        with_ext[n++] = 0x00u;

        char why[192] = { 0 };
        if (lc_chain_verify(with_ext, n, "www.example.com", why, sizeof why) == 0)
            ok("per-entry extensions are stepped over, not read as a length");
        else
            fail("a chain carrying certificate extensions was refused", why);
    }

    /* ---- and a machine with no certificate authorities at all ---- */
    {
        lc_chain_forget_roots();
        setenv("SSL_CERT_FILE", "/nonexistent/ca-certificates.crt", 1);
        setenv("SSL_CERT_DIR", "/nonexistent", 1);

        const entry full[] = { leaf, inter };
        must_refuse("no root store means refuse, not trust", full, 2, "www.example.com");
    }

    unlink(root_path);
    lc_chain_forget_roots();

    printf("\n%s\n", failures == 0 ? "the stranger path is verified the way the reference verifies it"
                                   : "THE STRANGER PATH IS NOT VERIFIED");
    return failures == 0 ? 0 : 1;
}
