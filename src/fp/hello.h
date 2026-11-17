/* Building the ClientHello from a fingerprint table.
 *
 * This is the single most consequential piece of the client. If it is wrong by one byte the
 * connection still works — the server accepts it, traffic flows, everything looks healthy — and the
 * client is simply identifiable on the wire, which is the one failure REALITY exists to prevent.
 * Hence the acceptance rule: the output is compared byte for byte against uTLS by tools/fp, and
 * nothing here is considered done until that comparison is clean. */
#ifndef LC_HELLO_H
#define LC_HELLO_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    LC_HELLO_OK = 0,
    LC_HELLO_BAD_TABLE,   /* the table does not parse, or declares a mode this build cannot honour */
    LC_HELLO_NO_SPACE,    /* the output buffer is too small for the message */
    LC_HELLO_NO_RANDOM,   /* the system refused to provide randomness */
    LC_HELLO_BAD_SNI,     /* the server name does not fit the wire encoding */
} lc_hello_err;

/* WHETHER A SERVER NAME CAN BE PUT ON THE WIRE AT ALL, asked here so that it is asked once.
 *
 * lc_hello_build refuses an empty name and one that will not fit the extension's length field, and
 * that refusal is correct. What was wrong is WHERE it was the only copy: a daemon takes its SNI on
 * the command line, an init script writes that line from a config that can be missing an option,
 * and an empty argument therefore reached a check that runs once per connection. The tunnel then
 * started, bound its LAN port, announced `sni ` with nothing after it, and failed every handshake
 * for as long as it ran — measured, not supposed.
 *
 * So the rule moves out where a caller holding a whole config can ask it BEFORE anything is
 * promised. It is the same rule and not a second copy of it: lc_hello_build asks this function.
 *
 * Returns non-zero when the name is usable. */
int lc_hello_sni_ok(const char *sni);

/* WHAT GOES IN THE server_name EXTENSION FOR A GIVEN NAME, which is not always the name: uTLS and
 * crypto/tls both write hostnameInSNI of it (vendor/utls/handshake_client.go:1364-1382; the
 * extension at vendor/utls/u_tls_extensions.go:129-161 writes nothing at all when it is empty). An
 * IP literal — bracketed or not, with a zone or not — has no SNI, and trailing dots are cut from a
 * name. What is written is always a prefix of the name, so the answer is its length: 0 for no
 * extension. */
size_t lc_hello_sni_len(const char *name);

/* What a refusal was, in a sentence for a person reading a log.
 *
 * ⚠️ THIS EXISTS BECAUSE ONE SENTENCE STOOD FOR FOUR CODES, and it named the wrong one. Every
 * failure out of lc_hello_build was reported as "the fingerprint table does not build a hello" —
 * including an empty SNI, which is an argument, and a refused getrandom, which is the kernel. A
 * router whose config lost its server name printed a sentence pointing at a file that was perfect,
 * and the search went to the file.
 *
 * The caller keeps its own context ("could not build the ClientHello"); this supplies only the
 * because-clause. */
const char *lc_hello_why(lc_hello_err e);

/* Where one group's public key sits in the finished message. */
typedef struct {
    uint16_t group;
    size_t   off;
    size_t   len;
} lc_hello_key_slot;

/* No fingerprint offers more than a handful of groups; four is already one more than any current
 * browser sends. Exceeding it is a table this build cannot honour, not something to truncate. */
#define LC_HELLO_MAX_SLOTS 4u

/* What the caller needs back from a built hello, beyond the bytes themselves. */
typedef struct {
    size_t            len;
    size_t            sid_off; /* where REALITY writes its authentication payload */
    size_t            sid_len; /* how wide the fingerprint made that field — REALITY needs 32 */
    lc_hello_key_slot slots[LC_HELLO_MAX_SLOTS];
    unsigned          slot_count;
    /* Whether the X25519 entry is to carry the X25519MLKEM768 entry's classical half rather than a
     * key of its own. The table says so for the profile it was cut from; see LC_FPT_FLAG_*. */
    int               key_share_reuse;
} lc_hello_out;

/* Writes a ClientHello handshake message (no record header) into out.
 *
 * key_share public keys are left ZEROED: this function knows the shape of the message, not the
 * cryptography. The caller fills them once the ephemeral keys exist, at the offsets reported in
 * `slots` — and the reported lengths are what the fingerprint demands, so a key of a different
 * size means the fingerprint and the key exchange disagree, which is a bug rather than something
 * to accommodate. */
lc_hello_err lc_hello_build(const uint8_t *table, size_t table_len,
                            const char *sni,
                            uint8_t *out, size_t out_cap,
                            lc_hello_out *info);

/* The same, for a table that carries quic_transport_parameters (LC_FPT_QUIC_PARAMS): `params` is
 * that extension's body as the QUIC transport encoded it, written where the table puts the
 * extension. The Hysteria2 plane's hello is built this way; lc_hello_build refuses such a table,
 * having no parameters to write. */
lc_hello_err lc_hello_build_quic(const uint8_t *table, size_t table_len, const char *sni,
                                 const uint8_t *params, size_t params_len, uint8_t *out,
                                 size_t out_cap, lc_hello_out *info);

/* THE SECOND HELLO, spliced out of the first the way uTLS mutates its own object after a
 * HelloRetryRequest — see the note above these in fp/hello.c. Both work in place on a hello of `cap`
 * bytes described by `info`, and keep `info` true: its length, and the offsets of the key shares
 * the caller has still to fill.
 *
 * lc_hello_splice_cookie echoes the server's cookie as a new extension at an index drawn over
 * [0, n-2), n being the extensions on the wire. lc_hello_splice_key_share replaces key_share with
 * one zeroed entry of `key_len` bytes for `group`, recorded as info->slots[0]. The cookie goes in
 * first. Both return 0, or -1 for a hello they cannot read or a result that would not fit;
 * lc_hello_splice_cookie returns -2 when the cookie would take the extension block past the sixteen
 * bits its length has. */
int lc_hello_splice_cookie(uint8_t *h, size_t cap, lc_hello_out *info, const uint8_t *cookie,
                           size_t cookie_len);
int lc_hello_splice_key_share(uint8_t *h, size_t cap, lc_hello_out *info, uint16_t group,
                              size_t key_len);

#endif
