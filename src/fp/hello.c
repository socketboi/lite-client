#include "fp/hello.h"

#include "core/buf.h"
#include "fp/fpt.h"
#include "core/rnd.h"
#include "tls/certcomp.h"
#include "tls/kex.h"
#include "core/wipe.h"

#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* The table is walked twice.
 *
 * Padding, when a fingerprint has it, is sized against the finished message — so the length of
 * everything else has to be known before the first byte is written. The alternative would be to
 * emit into a scratch buffer and memmove the tail once padding is known; walking a two-kilobyte
 * table a second time is cheaper than that, and leaves no second copy of the message in RAM. */

/* The widest extension list this file can reorder. Only the shuffle needs a bound — a table that is
 * replayed in its own order is walked as a stream and could carry any number — so a table above it
 * is refused only when it also asks to be shuffled. Firefox 148 and Chrome 133 carry seventeen
 * apiece; thirty-two is room for a browser to grow twice over without the number being a thing
 * anyone has to think about. */
#define LC_HELLO_MAX_EXTS 32u

typedef struct {
    size_t sni_len;
    size_t ext_fixed; /* every extension header plus every body except padding's */
    int    has_padding;

    /* Where each extension record starts, noted while sizing so the emitting pass can reach one
     * that is not next. `fixed` marks the records the shuffle must leave where they are. */
    unsigned ext_n;
    int      ext_over; /* more extensions than the arrays hold; only the shuffle cares */
    size_t   ext_off[LC_HELLO_MAX_EXTS];
    uint8_t  ext_fixed_pos[LC_HELLO_MAX_EXTS];

    /* The GREASE-ECH payload length THIS hello drew, tag included. Drawn in the sizing pass because
     * the length is part of the size, and handed to the emitting pass so the two agree. */
    int      has_ech;
    uint16_t ech_payload;
    int      no_random; /* a draw the sizing pass needed could not be made */

    /* The body of quic_transport_parameters, for a table that has one — the caller's, since the
     * transport encodes it. NULL outside lc_hello_build_quic, where such a table is refused. */
    const uint8_t *qtp;
    size_t         qtp_len;
    int            quic;
} hello_plan;

static int plan_extensions(lc_fpt *c, size_t sni_len, hello_plan *plan);
static lc_hello_err emit_extensions(lc_fpt *c, lc_buf *b, const hello_plan *plan,
                                    const uint8_t *order, const char *sni, size_t sni_len,
                                    size_t padding_body, int padding_emit,
                                    lc_hello_out *info);

/* GREASE values are drawn per connection, but NOT independently at every occurrence.
 *
 * TLS requires every group in key_share to appear in supported_groups. Chrome offers a GREASE group
 * in both, and it has to be the SAME value in both — drawing it twice produces a key share for a
 * group that was never offered, and the server answers illegal_parameter. That is precisely how this
 * was found: the hello matched uTLS byte for byte and was still refused by half the internet, while
 * Firefox, which offers no GREASE group, worked everywhere.
 *
 * The two GREASE EXTENSION types have the opposite constraint: they must DIFFER from each other. A
 * hello carries two of them, and drawing both from the same sixteen values makes them equal one time
 * in sixteen — which is a ClientHello with a duplicated extension type, and TLS parsers refuse those
 * outright. BoringSSL avoids it by flipping one bit of the second value when it collides with the
 * first, uTLS inherits that, and so does this.
 *
 * Worth recording how that one surfaced, because nothing pointed at it. The hello matched uTLS byte
 * for byte — the comparator ignores GREASE values, so a collision looked exactly like a good hello.
 * A REALITY server refused about one connection in fourteen and told the client nothing: the
 * handshake completed, the donor site was served, and only the server's own debug log said "failed
 * to read client hello". Feeding locally built hellos straight to the vendored parser reproduced it
 * offline, and every single refusal had two extensions with the same type.
 *
 * The cipher list may vary independently, and does. */
typedef struct {
    uint16_t group;
    int      have_group;
    /* Every GREASE extension type drawn so far. Sixteen is the whole space, so it cannot overflow
     * with values that matter. */
    uint16_t ext[16];
    unsigned ext_count;
} grease_ctx;

static int grease_group(grease_ctx *g, uint16_t *out)
{
    if (!g->have_group) {
        if (lc_rnd_grease(&g->group) != 0)
            return -1;
        g->have_group = 1;
    }
    *out = g->group;
    return 0;
}

/* A GREASE extension type, guaranteed distinct from the one drawn before it. The flip is of the high
 * nibble of both bytes at once: a GREASE value is 0x?a?a with its two bytes equal, so moving them
 * together lands on another valid GREASE value. */
static int grease_ext_type(grease_ctx *g, uint16_t *out)
{
    uint16_t v;
    if (lc_rnd_grease(&v) != 0)
        return -1;

    /* Compared against every value already used, not just the first. BoringSSL only has to guard
     * the second against the first because a hello carries exactly two; a table is free to ask for
     * more, and two of the later ones colliding is the same duplicated extension type with the same
     * consequence. Sixteen values, at most sixteen slots — the walk always terminates. */
    for (unsigned tries = 0; tries < 16u; tries++) {
        unsigned i = 0;
        while (i < g->ext_count && g->ext[i] != v)
            i++;
        if (i == g->ext_count)
            break;
        v ^= 0x1010u;
    }

    if (g->ext_count < sizeof g->ext / sizeof g->ext[0])
        g->ext[g->ext_count++] = v;
    *out = v;
    return 0;
}

/* The fixed part of the table, read identically by both passes. Keeping it in one function is what
 * stops the two walks from drifting apart; the pointers refer into the table blob, which outlives
 * the call. */
typedef struct {
    const uint8_t *name; /* the profile this table was captured from, not NUL-terminated */
    uint8_t        name_len;
    uint8_t        flags; /* LC_FPT_FLAG_* */
    uint16_t       legacy;
    uint8_t        sid_len;
    uint16_t       cipher_count;
    const uint8_t *ciphers; /* cipher_count entries of two bytes */
    uint8_t        comp_count;
    const uint8_t *comps;
} hello_head;

static void read_head(lc_fpt *c, hello_head *h)
{
    h->name_len = lc_fpt_u8(c);
    h->name = lc_fpt_bytes(c, h->name_len);
    h->flags = lc_fpt_u8(c);

    h->legacy = lc_fpt_u16(c);
    h->sid_len = lc_fpt_u8(c);

    h->cipher_count = lc_fpt_u16(c);
    h->ciphers = lc_fpt_bytes(c, (size_t)h->cipher_count * 2);

    h->comp_count = lc_fpt_u8(c);
    h->comps = lc_fpt_bytes(c, h->comp_count);
}

/* An extension type this file names only to keep it still. Defined here rather than pulled from the
 * TLS layer because nothing in this module parses a pre_shared_key — it only has to recognise one
 * in a table and refuse to move it, since RFC 8446 4.2.11 says it comes last or the hello is
 * illegal. No table of ours carries one; a table that did would still be emitted correctly. */
#define LC_EXT_PRE_SHARED_KEY 41u

/* WHETHER THIS PROFILE PERMUTES ITS EXTENSIONS — WHICH CHROME HAS DONE SINCE 106 AND WE DID NOT.
 *
 * uTLS builds every Chrome parrot from 106 onward through a wrapper:
 *
 *     Extensions: ShuffleChromeTLSExtensions([]TLSExtension{ ... })
 *
 * — at nine call sites. Six are the Chrome profiles from 106 to 133: the first is
 * HelloChrome_106_Shuffle (vendor/utls/u_parrots.go:529-552), the last is HelloChrome_133
 * (vendor/utls/u_parrots.go:894-917), and the four between them are given as a COUNT rather than
 * as line numbers on purpose: a list of bare numbers after a comma is a claim the sieve resolves
 * only as far as the first one, so five sixths of it would have looked checked and never been.
 * The other three are the PSK variants, HelloChrome_112_PSK_Shuf, HelloChrome_114_Padding_PSK_Shuf
 * and HelloChrome_115_PQ_PSK, further down the same file — this said six until 2026-09-23.
 * Each range runs from the `case` label to the wrapper call, because the profile's IDENTITY and
 * the fact that it is wrapped are two halves of one claim and a window around either half alone
 * shows only the other's absence.
 *
 * ⚠️ WHAT DOES THE SHUFFLING IS `shuffle_extensions` BELOW; this function only answers WHETHER.
 * They were one letter apart — `shuffles_extensions` and `shuffle_extensions` — until a reader
 * looking at this comment concluded the client checks a name and then emits in table order.
 *
 * Xray reaches exactly those: `"chrome": &utls.HelloChrome_Auto`
 * (vendor/Xray-core/transport/internet/tls/tls.go:257) with `HelloChrome_Auto = HelloChrome_133`
 * (vendor/utls/u_common.go:616). So the reference draws a fresh extension order for every single
 * connection, and this client replayed the captured one for ever.
 *
 * A REPLAYED ORDER IS NOT WRONG IN ANY ONE HELLO AND IS A MARK ACROSS TWO. Every order a capture
 * can hold is an order Chrome could have sent, so a single hello passes any test. What does not
 * pass is a second one: Chrome's order differs between two connections from the same browser, ours
 * did not differ between two connections from the same router — the same class of tell that
 * reality/spider.c fixed for the header block, read off the wire without decrypting anything.
 *
 * This tree already knew. `fp diff` grew a -shuffled flag whose comment says it outright —
 * "Chrome permutes its extensions on every connection since version 110, so demanding a fixed order
 * would be demanding the impossible" (tools/fp/diff.go:37-39) — and relaxes the order check to a
 * set check. Which is why `fp check -fp chrome` was green the whole time: the comparator stopped
 * asking the question the emitter was getting wrong.
 *
 * THE NAME IS THE PROFILE, and that is the reference's own key, not a heuristic invented here: uTLS
 * selects by ClientHelloID, Xray selects a ClientHelloID by the string, and a table's name field
 * exists to say which browser it was captured from. Edge is deliberately not included even though
 * it is Chromium — uTLS does not wrap HelloEdge_106 (u_parrots.go:2101), so neither do we.
 *
 * THE BOUNDARY THE NAME DOES NOT CARRY, because a name is a family and the rule has a version in
 * it: uTLS wraps Chrome 106 and later, and leaves 58 through 102 unwrapped (u_parrots.go:458 is
 * HelloChrome_100 and HelloChrome_102, with no wrapper on its Extensions). A table named `chrome`
 * but captured from a pre-106 browser would therefore be shuffled here and not there. It is a
 * boundary and not a defect: a capture that old disagrees with the reference in its cipher list
 * and its extension SET long before order matters, and `HelloChrome_Auto` — what Xray's "chrome"
 * resolves to — has been a shuffling profile since uTLS carried one. Carrying the rule properly
 * would mean a version in the table header, which is a format change and the user's call, not a
 * thing to invent here. Said out loud so the next reader meets a decision rather than a gap.
 *
 * THE LIST SHUFFLED IS THE PARROT'S OWN, NOT A CAPTURE — and this said the opposite could not be
 * helped. uTLS shuffles the literal list in its spec; a capture is already one draw of it, and the
 * skip-based swap loop below is not a uniform shuffle, so shuffling a capture composed the
 * reference's law with a frozen permutation. It was also measurable, not "a distribution over 15!
 * orders": the element that starts in the first or last movable slot stays there with probability
 * 2/17 where a uniform draw would give 1/16, so in a 400 000-draw simulation SNI led 11.8% of the
 * reference's Chrome hellos and 5.9% of ours, the capture having started it elsewhere. The
 * table now stores the spec's literal order (tools/fp/order.go reads it from the pinned uTLS source),
 * and this file needs no change for it: the loop was already the reference's. */
static int profile_shuffles(const hello_head *h)
{
    static const char chrome[] = "chrome";
    if (h->name == NULL || (size_t)h->name_len < sizeof chrome - 1u)
        return 0;
    for (size_t i = 0; i + 1u < sizeof chrome; i++) {
        uint8_t ch = h->name[i];
        if (ch >= 'A' && ch <= 'Z')
            ch = (uint8_t)(ch - 'A' + 'a');
        if (ch != (uint8_t)chrome[i])
            return 0;
    }
    return 1;
}

/* The reference's shuffle, swap for swap.
 *
 *     rand.New(...).Shuffle(len(exts), func(i, j int) {
 *         if skipShuf(i, exts) || skipShuf(j, exts) { return }
 *         exts[i], exts[j] = exts[j], exts[i]
 *     })                                     (vendor/utls/u_parrots.go:3045-3052)
 *
 * Go's Shuffle walks i from n-1 down to 1 drawing j uniformly in [0, i], and the closure declines
 * the swap when either end is positionally invariant — GREASE, padding or pre_shared_key
 * (u_parrots.go:3025-3033). Since an invariant element is therefore never moved, asking about the
 * element CURRENTLY at an index is the same question as asking about the one that started there,
 * which is what makes the flag array indexed by original position correct.
 *
 * Declining rather than redrawing is load-bearing: a redraw would make the permutation uniform over
 * the movable elements, and the reference's is not. The draw is unbiased (lc_rnd_below) because
 * Go's is — math/rand int31n rejects — and the whole point of this loop is that a census of many
 * hellos finds nothing.
 *
 * ⚠️ A DRAW THAT FAILS IS A HELLO THAT DOES NOT GO OUT, AND HERE THE REFERENCE DOES SOMETHING
 * ELSE — named because the reverse pass of the sieve asked, and because a divergence nobody wrote
 * down is one somebody re-discovers every run. uTLS does not stop when crypto/rand fails: it
 * shuffles anyway with the GLOBAL math/rand source and prints
 * `Warning: failed to use a cryptographically secure random number generator. The shuffle can be
 * deterministic.` to stdout (vendor/utls/u_parrots.go:3034-3044). Two rules of this tree say we
 * cannot do either half. The first is the whole contract of the randomness source: "A proxy that
 * quietly degrades to a weaker source when the good one is unavailable produces traffic that looks
 * fine and is not — so the contract is: bytes, or an error the caller must handle" (core/rnd.h),
 * and an order drawn from a predictable source is exactly traffic that looks fine and is not. The
 * second is a gate: no library file under src/ prints on its own account, so the warning has
 * nowhere to go and a silent weak shuffle would be strictly worse than uTLS's loud one.
 *
 * Falling back to the TABLE'S order — the other thing one might do — would put back exactly the
 * constant this removes, and silently. So: no bytes, no hello. On Linux the branch is very nearly
 * unreachable anyway, getrandom(2) answering only after the pool is up. */
static int shuffle_extensions(const hello_plan *plan, uint8_t *order)
{
    for (unsigned i = 0; i < plan->ext_n; i++)
        order[i] = (uint8_t)i;

    for (unsigned i = plan->ext_n; i > 1u; i--) {
        size_t j;
        if (lc_rnd_below(i, &j) != 0)
            return -1;
        unsigned a = i - 1u;
        if (plan->ext_fixed_pos[order[a]] || plan->ext_fixed_pos[order[(unsigned)j]])
            continue;
        uint8_t t = order[a];
        order[a] = order[(unsigned)j];
        order[(unsigned)j] = t;
    }
    return 0;
}

/* The rule itself. Zero because a ClientHello without a server_name is not the fingerprint the
 * table describes, and 0xfff0 because the name sits inside three nested length fields — the
 * extension, the list, the entry — and the outermost is sixteen bits with the other two headers
 * ahead of it. Both halves are what lc_hello_build has always applied; see hello.h for why they are
 * reachable from outside now. */
int lc_hello_sni_ok(const char *sni)
{
    if (sni == NULL)
        return 0;
    size_t n = strlen(sni);
    return n != 0u && n <= 0xfff0u;
}

/* net.ParseIP's IPv4 half, through netip.ParseAddr as Go 1.26 and 1.27 have it: four decimal
 * fields, each 0..255, none with a leading zero. */
static int is_ipv4(const char *s, size_t n)
{
    unsigned fields = 0;
    size_t   i = 0;
    while (fields < 4u) {
        size_t   start = i;
        unsigned v = 0;
        while (i < n && s[i] >= '0' && s[i] <= '9' && i - start < 3u)
            v = v * 10u + (unsigned)(s[i++] - '0');
        if (i == start || v > 255u || (s[start] == '0' && i - start > 1u))
            return 0;
        fields++;
        if (fields < 4u) {
            if (i >= n || s[i] != '.')
                return 0;
            i++;
        }
    }
    return i == n;
}

size_t lc_hello_sni_len(const char *name)
{
    size_t n = strlen(name);

    /* The literal test runs on the host with its brackets and zone taken off... */
    const char *host = name;
    size_t      hn = n;
    if (hn >= 2u && host[0] == '[' && host[hn - 1u] == ']') {
        host++;
        hn -= 2u;
    }
    for (size_t i = hn; i > 1u; i--)
        if (host[i - 1u] == '%') {
            hn = i - 1u;
            break;
        }
    char lit[64];
    if (is_ipv4(host, hn))
        return 0;
    if (hn < sizeof lit) {
        unsigned char a6[16];
        memcpy(lit, host, hn);
        lit[hn] = '\0';
        if (inet_pton(AF_INET6, lit, a6) == 1)
            return 0;
    }

    /* ...and the dots come off the name itself, brackets and all. */
    while (n > 0u && name[n - 1u] == '.')
        n--;
    return n;
}

const char *lc_hello_why(lc_hello_err e)
{
    switch (e) {
    case LC_HELLO_OK:
        return "no failure";
    case LC_HELLO_BAD_TABLE:
        return "the fingerprint table does not parse, or asks for something this build cannot emit";
    case LC_HELLO_NO_SPACE:
        return "the hello does not fit the buffer it was given";
    case LC_HELLO_NO_RANDOM:
        return "the system refused to provide randomness";
    case LC_HELLO_BAD_SNI:
        return "the server name is empty or too long to put on the wire";
    }
    /* Not reachable while the switch above is exhaustive, and -Werror=switch keeps it that way.
     * Present because a value cast in from outside the enum must not fall off the end of a function
     * that returns a pointer somebody is about to print. */
    return "unknown";
}

static lc_hello_err build(const uint8_t *table, size_t table_len, const char *sni, int quic,
                          const uint8_t *qtp, size_t qtp_len, uint8_t *out, size_t out_cap,
                          lc_hello_out *info);

lc_hello_err lc_hello_build(const uint8_t *table, size_t table_len,
                            const char *sni,
                            uint8_t *out, size_t out_cap,
                            lc_hello_out *info)
{
    return build(table, table_len, sni, 0, NULL, 0, out, out_cap, info);
}

lc_hello_err lc_hello_build_quic(const uint8_t *table, size_t table_len, const char *sni,
                                 const uint8_t *params, size_t params_len, uint8_t *out,
                                 size_t out_cap, lc_hello_out *info)
{
    return build(table, table_len, sni, 1, params, params_len, out, out_cap, info);
}

static lc_hello_err build(const uint8_t *table, size_t table_len, const char *sni, int quic,
                          const uint8_t *qtp, size_t qtp_len, uint8_t *out, size_t out_cap,
                          lc_hello_out *info)
{
    if (!lc_hello_sni_ok(sni))
        return LC_HELLO_BAD_SNI;
    /* As hostnameInSNI puts it on the wire — see lc_hello_sni_len. 0 leaves the extension out. */
    size_t sni_len = lc_hello_sni_len(sni);

    /* What the table needs against what this build can emit, decided before anything is built. The
     * check existed and nothing called it, which made the whole requirement block decorative: a
     * table asking for a key exchange this client cannot do would have failed halfway through the
     * walk instead of being refused with a reason. Callers wanting that reason ask lc_fpt_supported
     * themselves; here it is enough to stop. */
    char why[160];
    if (lc_fpt_supported_with(table, table_len, quic ? 1u << LC_FPT_QUIC_PARAMS : 0u, why,
                              sizeof why) != 0)
        return LC_HELLO_BAD_TABLE;

    /* ---- pass one: how long is everything that is not padding ---- */
    lc_fpt c;
    if (lc_fpt_open(&c, table, table_len, NULL) != 0)
        return LC_HELLO_BAD_TABLE;

    hello_head head;
    read_head(&c, &head);

    hello_plan plan = { .sni_len = sni_len, .qtp = qtp, .qtp_len = qtp_len, .quic = quic };
    if (plan_extensions(&c, sni_len, &plan) != 0 || lc_fpt_failed(&c))
        return plan.no_random ? LC_HELLO_NO_RANDOM : LC_HELLO_BAD_TABLE;

    /* WHETHER TO PAD AT ALL, WHICH IS A QUESTION THE REFERENCE ASKS PER HELLO.
     *
     * This padded to a target frozen into the fingerprint table — the number `fp table` copied out
     * of one capture — and emitted the extension on every hello that named it. uTLS does neither.
     * Its padding extension has no length of its own until it is asked:
     *
     *     func (e *UtlsPaddingExtension) Len() int {
     *         if e.WillPad { return 4 + e.PaddingLen } else { return 0 }
     *                                    (vendor/utls/u_tls_extensions.go:1073-1079)
     *
     * and WillPad comes from BoringPaddingStyle, which is BoringSSL's rule and pads only inside one
     * window:
     *
     *     if unpaddedLen > 0xff && unpaddedLen < 0x200 {
     *         paddingLen := 0x200 - unpaddedLen
     *         if paddingLen >= 4+1 { paddingLen -= 4 } else { paddingLen = 1 }
     *         return paddingLen, true
     *     }
     *     return 0, false                (vendor/utls/u_tls_extensions.go:1126-1137)
     *
     * Outside that window the extension is not written AT ALL — Len() is zero, so it contributes
     * nothing and does not appear in the hello. A client that always writes it is distinguishable
     * from every BoringSSL-shaped client by the one case that matters: a hello already at or past
     * 512 bytes, which is what a long SNI produces. We were emitting `0015 0000` — an empty padding
     * extension, a thing no browser sends — or a 512-byte hello where the reference sends 513.
     *
     * The four-byte subtraction is the whole reason `before` is not the answer directly: uTLS
     * measures the hello with the padding extension ENTIRELY absent (u_conn.go:605-623 skips it
     * while summing, then calls Update on the sum), and `before` counts its four-byte header.
     *
     * Reachable only through a table whose capture carried the extension — ios, edge and qq do;
     * the shipped Firefox table does not — which is why this went unseen and not why it was right.
     */
    size_t padding_body = 0;
    int    padding_emit = 0;
    if (plan.has_padding) {
        /* Everything but the padding body: handshake header, the fixed fields, the extension block
         * length, and every extension header and body including padding's own four-byte header
         * (ext_fixed already counts it). */
        size_t before = 4u                          /* handshake type + 24-bit length */
                        + 2u                        /* legacy_version */
                        + 32u                       /* random */
                        + 1u + (size_t)head.sid_len /* session_id */
                        + 2u + (size_t)head.cipher_count * 2u
                        + 1u + (size_t)head.comp_count
                        + 2u                        /* extension block length */
                        + plan.ext_fixed;
        size_t unpadded = before - 4u;
        if (unpadded > 0xffu && unpadded < 0x200u) {
            size_t pad = 0x200u - unpadded;
            padding_body = pad >= 5u ? pad - 4u : 1u;
            padding_emit = 1;
        }
    }

    /* ---- the order the extensions go out in ---- */
    uint8_t  order[LC_HELLO_MAX_EXTS];
    uint8_t *use_order = NULL;
    if (profile_shuffles(&head)) {
        /* Refused rather than replayed in table order: a Chrome table this file cannot reorder is a
         * Chrome hello with a constant extension order, which is the defect, not a degraded mode.
         * Unreachable with any real profile — see LC_HELLO_MAX_EXTS. */
        if (plan.ext_over)
            return LC_HELLO_BAD_TABLE;
        if (shuffle_extensions(&plan, order) != 0)
            return LC_HELLO_NO_RANDOM;
        use_order = order;
    }

    /* ---- pass two: write it ---- */
    if (lc_fpt_open(&c, table, table_len, NULL) != 0)
        return LC_HELLO_BAD_TABLE;
    read_head(&c, &head);
    if (lc_fpt_failed(&c) || head.ciphers == NULL || head.comps == NULL)
        return LC_HELLO_BAD_TABLE;

    memset(info, 0, sizeof *info);
    info->key_share_reuse = (head.flags & LC_FPT_FLAG_KEY_SHARE_REUSE) != 0u;

    lc_buf b;
    lc_buf_init(&b, out, out_cap);

    lc_buf_u8(&b, 0x01);   /* handshake type: client_hello */
    size_t len_at = b.len; /* the 24-bit length is patched in once the body is written */
    lc_buf_u24(&b, 0);

    size_t body_start = b.len;
    lc_buf_u16(&b, head.legacy);

    uint8_t *random = lc_buf_reserve(&b, 32);
    if (random == NULL)
        return LC_HELLO_NO_SPACE;
    if (lc_rnd(random, 32) != 0)
        return LC_HELLO_NO_RANDOM;

    lc_buf_u8(&b, head.sid_len);
    info->sid_off = b.len;
    info->sid_len = head.sid_len;
    uint8_t *sid = lc_buf_reserve(&b, head.sid_len);
    if (sid == NULL)
        return LC_HELLO_NO_SPACE;
    /* Random for now. On a live connection REALITY overwrites exactly these bytes with its
     * authentication payload, which is why the offset is reported back to the caller. */
    if (lc_rnd(sid, head.sid_len) != 0)
        return LC_HELLO_NO_RANDOM;

    lc_buf_u16(&b, (uint16_t)((size_t)head.cipher_count * 2u));
    for (uint16_t i = 0; i < head.cipher_count; i++) {
        uint16_t v = (uint16_t)((uint16_t)head.ciphers[i * 2] << 8 | head.ciphers[i * 2 + 1]);
        if (v == LC_FPT_GREASE && lc_rnd_grease(&v) != 0)
            return LC_HELLO_NO_RANDOM;
        lc_buf_u16(&b, v);
    }

    lc_buf_u8(&b, head.comp_count);
    lc_buf_write(&b, head.comps, head.comp_count);

    size_t ext_len_at = b.len;
    lc_buf_u16(&b, 0); /* patched below */
    size_t ext_start = b.len;

    lc_hello_err err = emit_extensions(&c, &b, &plan, use_order, sni, sni_len, padding_body,
                                       padding_emit, info);
    if (err != LC_HELLO_OK)
        return err;
    if (lc_fpt_failed(&c))
        return LC_HELLO_BAD_TABLE;
    if (b.err)
        return LC_HELLO_NO_SPACE;

    size_t ext_bytes = b.len - ext_start;
    out[ext_len_at] = (uint8_t)(ext_bytes >> 8);
    out[ext_len_at + 1] = (uint8_t)ext_bytes;

    size_t body_bytes = b.len - body_start;
    out[len_at] = (uint8_t)(body_bytes >> 16);
    out[len_at + 1] = (uint8_t)(body_bytes >> 8);
    out[len_at + 2] = (uint8_t)body_bytes;

    info->len = b.len;
    return LC_HELLO_OK;
}

/* plan_extensions walks the extension list without emitting, accumulating the length of everything
 * except the padding body. Returns -1 if the table declares a mode this build cannot honour —
 * refusing the whole table, because a skipped extension is exactly a wrong-but-working hello. */
static int plan_extensions(lc_fpt *c, size_t sni_len, hello_plan *plan)
{
    uint16_t ext_count = lc_fpt_u16(c);
    for (uint16_t i = 0; i < ext_count; i++) {
        /* Where this record begins, taken before anything in it is read. No length depends on it —
         * this pass measures — but the emitter may need to reach records out of order, and a stream
         * cursor is the only thing that knows where they are.
         *
         * The type used to be read and dropped here on the grounds that no length depends on WHICH
         * extension it is. That is still true of the length and no longer true of the record: the
         * type decides whether the shuffle may move it. */
        size_t   at = lc_fpt_tell(c);
        uint16_t type = lc_fpt_u16(c);
        uint8_t  mode = lc_fpt_u8(c);
        plan->ext_fixed += 4u; /* type + length */

        if (plan->ext_n < LC_HELLO_MAX_EXTS) {
            plan->ext_off[plan->ext_n] = at;
            /* The three uTLS calls positionally invariant, by the identity a table has for each:
             * GREASE is the stored type, padding is the mode, pre_shared_key is its own number. */
            plan->ext_fixed_pos[plan->ext_n] =
                (uint8_t)(type == LC_FPT_GREASE || type == LC_EXT_PRE_SHARED_KEY ||
                          mode == LC_FPT_PADDING);
            plan->ext_n++;
        } else {
            plan->ext_over = 1;
        }

        switch (mode) {
        case LC_FPT_LITERAL: {
            uint16_t n = lc_fpt_u16(c);
            lc_fpt_bytes(c, n);
            uint8_t g = lc_fpt_u8(c);
            lc_fpt_bytes(c, (size_t)g * 2);
            /* compress_certificate goes out exactly as captured since the client gained the other
             * two decoders, so there is no longer a per-extension exception here. The emitter
             * refuses a table whose body differs, which is what keeps the two passes agreeing. */
            plan->ext_fixed += n;
            break;
        }
        case LC_FPT_SNI:
            /* No name, no extension: its header comes off again. */
            if (sni_len == 0u)
                plan->ext_fixed -= 4u;
            else
                plan->ext_fixed += 5u + sni_len;
            break;
        case LC_FPT_KEY_SHARE: {
            uint8_t groups = lc_fpt_u8(c);
            size_t  body = 2u;
            for (uint8_t g = 0; g < groups; g++) {
                (void)lc_fpt_u16(c); /* group */
                body += 4u + (size_t)lc_fpt_u16(c);
            }
            plan->ext_fixed += body;
            break;
        }
        case LC_FPT_RANDOM_PAYLOAD:
            plan->ext_fixed += (size_t)lc_fpt_u16(c);
            break;
        case LC_FPT_PADDING:
            if (plan->has_padding)
                return -1; /* two padding extensions cannot both be satisfied */
            plan->has_padding = 1;
            /* The captured target is consumed and NOT used. uTLS does not pad to a number taken
             * from a capture — it recomputes one per hello, and often declines to pad at all. */
            (void)lc_fpt_u16(c);
            break;
        case LC_FPT_ECH_GREASE: {
            (void)lc_fpt_u16(c); /* kdf */
            /* The candidate list, counted and skipped: the plan needs only the SIZE this extension
             * will occupy, and every candidate is the same two bytes on the wire whichever one the
             * draw lands on. Refused here as well as at the emit pass, because a table that cannot
             * be honoured should be rejected before anything is built from it. */
            unsigned naead = lc_fpt_u8(c);
            if (naead == 0u || naead > LC_FPT_ECH_MAX_AEADS)
                return -1;
            for (unsigned k = 0; k < naead; k++) {
                /* The tag added below is sixteen bytes for exactly these three, and uTLS panics on
                 * anything else (vendor/utls/u_hpke.go:29-36) — so a table naming another is one
                 * the reference could never have rendered. */
                uint16_t a = lc_fpt_u16(c);
                if (a != 0x0001u && a != 0x0002u && a != 0x0003u)
                    return -1;
            }
            size_t   enc = lc_fpt_u16(c);
            unsigned nlen = lc_fpt_u8(c);
            if (nlen == 0u || nlen > LC_FPT_ECH_MAX_LENS || plan->has_ech)
                return -1;
            uint16_t lens[LC_FPT_ECH_MAX_LENS];
            for (unsigned k = 0; k < nlen; k++)
                lens[k] = lc_fpt_u16(c);

            /* THE PAYLOAD LENGTH IS DRAWN PER HELLO, like the suite: `rndIndex` over
             * CandidatePayloadLens, then `cipherLen(aead, len)` = len + 16
             * (vendor/utls/u_ech.go:160-166, u_hpke.go:29-36). Chrome's list is 128, 160, 192, 224
             * (u_ech.go:328); a single length copied off one capture made every Chrome hello of
             * this client one of four lengths the reference spreads evenly over. Drawn here, in the
             * sizing pass, because the length is part of the size. */
            size_t pick = 0;
            if (lc_rnd_below(nlen, &pick) != 0) {
                plan->no_random = 1;
                return -1;
            }
            if ((size_t)lens[pick] + 16u > 0xffffu)
                return -1;
            plan->has_ech = 1;
            plan->ech_payload = (uint16_t)(lens[pick] + 16u);
            /* type, kdf, aead, config_id, and the two length fields: ten bytes of structure. */
            plan->ext_fixed += 10u + enc + plan->ech_payload;
            break;
        }
        case LC_FPT_QUIC_PARAMS:
            /* The transport's own bytes, whose length is the whole of what this pass needs. A
             * caller that brought none cannot build this table: see LC_FPT_QUIC_PARAMS. */
            if (!plan->quic || plan->qtp_len > 0xffffu || (plan->qtp == NULL && plan->qtp_len != 0u))
                return -1;
            plan->ext_fixed += plan->qtp_len;
            break;
        default:
            return -1;
        }
    }
    return lc_fpt_failed(c) ? -1 : 0;
}

/* One extension record, from the cursor. Split out of the walk so the walk can decide what "next"
 * means: sequential for a profile that replays its capture, and a drawn order for one that does not.
 *
 * The GREASE context is the caller's because it spans the whole hello — the group has to be the
 * same in supported_groups and key_share, and each GREASE extension type has to differ from the
 * ones before it. Neither depends on the order the records are visited in: the group is drawn once
 * and cached, and the extension types are compared against every value already used. The two GREASE
 * extensions keep their positions besides, so even the order they are drawn in is unchanged. */
static lc_hello_err emit_one_extension(lc_fpt *c, lc_buf *b, grease_ctx *gr, const hello_plan *plan,
                                       const char *sni,
                                       size_t sni_len, size_t padding_body, int padding_emit,
                                       lc_hello_out *info);

static lc_hello_err emit_extensions(lc_fpt *c, lc_buf *b, const hello_plan *plan,
                                    const uint8_t *order, const char *sni, size_t sni_len,
                                    size_t padding_body, int padding_emit,
                                    lc_hello_out *info)
{
    grease_ctx gr;
    memset(&gr, 0, sizeof gr);

    uint16_t ext_count = lc_fpt_u16(c);
    for (uint16_t i = 0; i < ext_count; i++) {
        if (order != NULL) {
            /* The sizing pass counted every record and the arrays hold them all, or the build was
             * refused before reaching here — so the two counts agree and the seek always lands on a
             * record start. */
            if ((size_t)i >= (size_t)plan->ext_n)
                return LC_HELLO_BAD_TABLE;
            lc_fpt_seek(c, plan->ext_off[order[i]]);
        }
        lc_hello_err e =
            emit_one_extension(c, b, &gr, plan, sni, sni_len, padding_body, padding_emit, info);
        if (e != LC_HELLO_OK)
            return e;
    }
    return LC_HELLO_OK;
}

static lc_hello_err emit_one_extension(lc_fpt *c, lc_buf *b, grease_ctx *gr, const hello_plan *plan,
                                       const char *sni,
                                       size_t sni_len, size_t padding_body, int padding_emit,
                                       lc_hello_out *info)
{
    uint16_t type = lc_fpt_u16(c);
    uint8_t  mode = lc_fpt_u8(c);

    if (type == LC_FPT_GREASE && grease_ext_type(gr, &type) != 0)
        return LC_HELLO_NO_RANDOM;

    switch (mode) {
    case LC_FPT_LITERAL: {
        uint16_t       n = lc_fpt_u16(c);
        const uint8_t *data = lc_fpt_bytes(c, n);
        uint8_t        gcount = lc_fpt_u8(c);
        if (data == NULL)
            return LC_HELLO_BAD_TABLE;

        /* THE ONE EXTENSION WHOSE BODY IS CHECKED — EVERY ALGORITHM IN IT, NOT THE LIST AS A
         * WHOLE.
         *
         * compress_certificate is a promise: RFC 8879 §4 says a client MUST be able to
         * decompress anything it advertised, and the server picks from the list by its own
         * preference, not ours. So a table naming an algorithm lc_certcomp_open cannot open
         * would produce a hello whose ordinary reply we abort on — louder on the wire than any
         * missing byte. That is what is refused here.
         *
         * ⚠️ AND IT IS NOT AN EQUALITY CHECK, WHICH IS THE BUG THIS PARAGRAPH REPLACES. The
         * list is a PROPERTY OF THE PROFILE, not of this client: uTLS gives Firefox 148 all
         * three (u_parrots.go:1572-1576) and Chrome exactly one, brotli (u_parrots.go:162), and
         * both are correct hellos. Demanding that the table equal OUR list refused every Chrome
         * table outright — `the fingerprint table does not build a hello`, on a device whose
         * REALITY plane had been working, found by running one. The client's business is being
         * able to open what the table promises, and it can: all three are built in.
         *
         * The body therefore goes out exactly as captured, and each identifier in it is checked
         * against what the decompressor accepts. LC_CERTCOMP_EXT_BODY stays the definition of
         * "what this client can open" and is read here as a set, not as a template. */
        if (type == LC_EXT_COMPRESS_CERTIFICATE) {
            static const uint8_t openable[] = LC_CERTCOMP_EXT_BODY;
            /* `algorithms<2..2^8-2>`: one length byte, then two bytes each. A body that does not
             * have that shape is not a list we can reason about at all. */
            if (n < 3u || (size_t)data[0] + 1u != (size_t)n || (n - 1u) % 2u != 0u)
                return LC_HELLO_BAD_TABLE;
            for (uint16_t k = 1u; k + 1u < n; k += 2u) {
                unsigned alg = (unsigned)data[k] << 8 | data[k + 1u];
                int      known = 0;
                for (size_t j = 1u; j + 1u < sizeof openable; j += 2u)
                    if (((unsigned)openable[j] << 8 | openable[j + 1u]) == alg)
                        known = 1;
                if (!known)
                    return LC_HELLO_BAD_TABLE;
            }
        }

        lc_buf_u16(b, type);
        lc_buf_u16(b, n);
        uint8_t *body = lc_buf_reserve(b, n);
        if (body == NULL)
            return LC_HELLO_NO_SPACE;
        memcpy(body, data, n);

        /* Inline GREASE — the value a list-shaped extension carries inside its body — is
         * redrawn at the offsets the table records. Copying the captured value would freeze a
         * field that has to vary per connection. */
        for (uint8_t g = 0; g < gcount; g++) {
            uint16_t off = lc_fpt_u16(c);
            if ((size_t)off + 1 >= (size_t)n)
                return LC_HELLO_BAD_TABLE;
            uint16_t v;
            /* supported_groups is the one list whose inline GREASE has to agree with the
             * key_share entry below; everywhere else an independent draw is correct. */
            int rc = (type == 0x000au) ? grease_group(gr, &v) : lc_rnd_grease(&v);
            if (rc != 0)
                return LC_HELLO_NO_RANDOM;
            body[off] = (uint8_t)(v >> 8);
            body[off + 1] = (uint8_t)v;
        }
        break;
    }

    case LC_FPT_SNI:
        /* An empty SNIExtension has no length and writes nothing (vendor/utls/u_tls_extensions.go:
         * 129-137, :139-146). */
        if (sni_len == 0u)
            break;
        lc_buf_u16(b, type);
        lc_buf_u16(b, (uint16_t)(5 + sni_len));
        lc_buf_u16(b, (uint16_t)(sni_len + 3)); /* server_name_list length */
        lc_buf_u8(b, 0x00);                     /* host_name */
        lc_buf_u16(b, (uint16_t)sni_len);
        lc_buf_write(b, (const uint8_t *)sni, sni_len);
        break;

    case LC_FPT_KEY_SHARE: {
        uint8_t groups = lc_fpt_u8(c);
        /* The bodies are emitted first into the output, then the two length fields are patched:
         * the total is not known until every key length has been read from the table. */
        lc_buf_u16(b, type);
        size_t ext_len_at = b->len;
        lc_buf_u16(b, 0);
        size_t list_len_at = b->len;
        lc_buf_u16(b, 0);
        size_t list_start = b->len;

        for (uint8_t g = 0; g < groups; g++) {
            uint16_t grp = lc_fpt_u16(c);
            uint16_t klen = lc_fpt_u16(c);
            if (grp == LC_FPT_GREASE && grease_group(gr, &grp) != 0)
                return LC_HELLO_NO_RANDOM;
            lc_buf_u16(b, grp);
            lc_buf_u16(b, klen);
            /* Zeroed: this module builds the shape, the crypto layer fills the keys. Where
             * each one goes is reported back, because only the caller knows which groups it
             * can actually produce a key for — and a group it cannot is a table that does not
             * match this build. */
            if (info->slot_count == LC_HELLO_MAX_SLOTS)
                return LC_HELLO_BAD_TABLE;
            info->slots[info->slot_count].group = grp;
            info->slots[info->slot_count].off = b->len;
            info->slots[info->slot_count].len = klen;
            info->slot_count++;
            lc_buf_zero(b, klen);
        }
        if (b->err)
            return LC_HELLO_NO_SPACE;

        size_t list_bytes = b->len - list_start;
        b->p[list_len_at] = (uint8_t)(list_bytes >> 8);
        b->p[list_len_at + 1] = (uint8_t)list_bytes;
        size_t ext_bytes = b->len - list_len_at;
        b->p[ext_len_at] = (uint8_t)(ext_bytes >> 8);
        b->p[ext_len_at + 1] = (uint8_t)ext_bytes;
        break;
    }

    case LC_FPT_RANDOM_PAYLOAD: {
        uint16_t n = lc_fpt_u16(c);
        lc_buf_u16(b, type);
        lc_buf_u16(b, n);
        uint8_t *payload = lc_buf_reserve(b, n);
        if (payload == NULL)
            return LC_HELLO_NO_SPACE;
        if (lc_rnd(payload, n) != 0)
            return LC_HELLO_NO_RANDOM;
        break;
    }

    case LC_FPT_PADDING:
        (void)lc_fpt_u16(c); /* the captured target, which the rule in pass one does not use */
        /* Len() == 0: outside BoringSSL's window the extension is not written at all, so the
         * hello has one fewer extension rather than an empty one. The extension block length is
         * patched from what was actually emitted, so nothing else has to know. */
        if (!padding_emit)
            break;
        lc_buf_u16(b, type);
        lc_buf_u16(b, (uint16_t)padding_body);
        lc_buf_zero(b, padding_body);
        break;

    case LC_FPT_ECH_GREASE: {
        /* A real ECHClientHello in its outer form, with random contents. This is NOT a blob of
         * random bytes: servers parse this extension, and one that does not parse gets the whole
         * hello rejected with decode_error — which is exactly how the first live handshake
         * failed against every public server tried. */
        uint16_t kdf = lc_fpt_u16(c);
        unsigned naead = lc_fpt_u8(c);
        if (naead == 0u || naead > LC_FPT_ECH_MAX_AEADS)
            return LC_HELLO_BAD_TABLE;
        uint16_t cand[LC_FPT_ECH_MAX_AEADS];
        for (unsigned i = 0; i < naead; i++)
            cand[i] = lc_fpt_u16(c);
        uint16_t enc_len = lc_fpt_u16(c);
        /* The candidate lengths are skipped: the sizing pass has drawn this hello's one already, and
         * the two passes must write the same length. */
        unsigned nlen = lc_fpt_u8(c);
        if (nlen == 0u || nlen > LC_FPT_ECH_MAX_LENS || !plan->has_ech)
            return LC_HELLO_BAD_TABLE;
        for (unsigned k = 0; k < nlen; k++)
            (void)lc_fpt_u16(c);
        uint16_t payload_len = plan->ech_payload;
        uint16_t aead;

        /* THE CIPHER SUITE IS DRAWN PER HELLO, because that is what the browser does, and the
         * candidates are the TABLE'S — which is the half this comment could not say until the
         * format carried them.
         *
         * uTLS draws an index over CandidateCipherSuites for every ClientHello (`rand.Int` over
         * len(g.CandidateCipherSuites), vendor/utls/u_ech.go:99-107). A constant stood here
         * instead: whichever way the coin came down on the day the table was made, sent on every
         * connection for ever — in the clear, in the first packet, where a browser is a coin flip.
         * Sixteen captures gave seven of one value and nine of the other, so two builds of this
         * client disagreed with each other.
         *
         * Drawn with lc_rnd_below rather than a masked byte: the list is whatever the parrot
         * defines, and `coin & 1` is only unbiased for exactly two. It is two for the Firefox
         * parrots that carry this extension (u_parrots.go:1533, 1656) and ONE for Chrome's, whose
         * parrots take BoringGREASEECH (vendor/utls/u_ech.go:320-330) — this said "two for both"
         * until 2026-09-23 — so writing the draw to depend on any count would put the old fault
         * back one level down. */
        {
            size_t pick = 0;
            if (lc_rnd_below((unsigned)naead, &pick) != 0)
                return LC_HELLO_NO_RANDOM;
            aead = cand[pick];
        }

        lc_buf_u16(b, type);
        lc_buf_u16(b, (uint16_t)(10u + enc_len + payload_len));
        lc_buf_u8(b, 0x00); /* outer */
        lc_buf_u16(b, kdf);
        lc_buf_u16(b, aead);

        uint8_t *cfg = lc_buf_reserve(b, 1u);
        if (cfg == NULL)
            return LC_HELLO_NO_SPACE;
        if (lc_rnd(cfg, 1u) != 0)
            return LC_HELLO_NO_RANDOM;

        /* `enc` IS AN X25519 PUBLIC KEY, NOT THIRTY-TWO RANDOM BYTES — and the difference is one
         * bit that half of our connections got wrong.
         *
         * The field is HPKE's encapsulated key, and uTLS produces it the only way it can be
         * produced: by running the sender half of HPKE against a dummy recipient key —
         * `g.EncapsulatedKey, _, err = hpke.NewSender(publicKey, kdf, aead, []byte{})`
         * (vendor/utls/u_ech.go:150), which generates an ephemeral key and returns
         * `privEph.PublicKey().Bytes()` (GOROOT/src/crypto/hpke/kem.go:235-252, go1.27.3).
         * For the default KEM that is X25519, so the
         * value is a u-coordinate reduced mod 2^255-19 and its most significant bit is therefore
         * always zero: byte 31 of a reference `enc` never exceeds 0x7f.
         *
         * Filled from the CSPRNG, that bit is set half the time. One test, at a fixed offset in
         * the last extension of the first packet, flags half of this client's connections on
         * sight and any client seen twice with probability three quarters. Nothing about the
         * handshake notices, because a GREASE ECH is never decrypted by anybody.
         *
         * The gate could not see it either: tools/fp/diff.go:142-147 compares this extension by
         * body length alone, which was right.
         *
         * A real key pair is generated rather than the top bit merely cleared, because clearing
         * it leaves the other 255 bits uniform and a u-coordinate is not: the value must be
         * below 2^255-19, and 19 values in every 2^255 are not. That is far beyond anything
         * observable, and generating the key is one scalar multiplication once per connection —
         * the honest construction costs nothing worth the argument. The private half is dropped
         * on the floor here, which is what makes this GREASE rather than ECH. */
        lc_buf_u16(b, enc_len);
        uint8_t *enc = lc_buf_reserve(b, enc_len);
        if (enc == NULL)
            return LC_HELLO_NO_SPACE;
        if (enc_len == LC_X25519_KEY) {
            uint8_t throwaway_priv[LC_X25519_KEY];
            int     ok = lc_x25519_keygen(throwaway_priv, enc) == 0;
            lc_wipe(throwaway_priv, sizeof throwaway_priv);
            if (!ok)
                return LC_HELLO_NO_RANDOM;
        } else if (lc_rnd(enc, enc_len) != 0) {
            /* A table declaring some other width is not describing X25519, and there is nothing
             * better to put there than what it asked for. */
            return LC_HELLO_NO_RANDOM;
        }

        lc_buf_u16(b, payload_len);
        uint8_t *payload = lc_buf_reserve(b, payload_len);
        if (payload == NULL)
            return LC_HELLO_NO_SPACE;
        if (lc_rnd(payload, payload_len) != 0)
            return LC_HELLO_NO_RANDOM;
        break;
    }

    case LC_FPT_QUIC_PARAMS:
        /* Written as the transport encoded it, the order and the widths included: uTLS copies the
         * fork's marshalled parameters into this extension (tls_conn_utls.go:136-152) and so does
         * this. */
        if (!plan->quic)
            return LC_HELLO_BAD_TABLE;
        lc_buf_u16(b, type);
        lc_buf_u16(b, (uint16_t)plan->qtp_len);
        if (plan->qtp_len != 0u)
            lc_buf_write(b, plan->qtp, plan->qtp_len);
        break;

    default:
        return LC_HELLO_BAD_TABLE;
    }
    return LC_HELLO_OK;
}

/* ---- the second hello, after a HelloRetryRequest ----------------------------- */

/* ⚠️ THE SECOND HELLO IS THE FIRST ONE WITH ONE EXTENSION REPLACED, AND THAT IS MEASURED RATHER
 * THAN ASSUMED. tools/fp grew a `retry` subcommand for exactly this question — it drives uTLS
 * through a synthetic HelloRetryRequest and dumps both messages — and the answer is unambiguous:
 * against the shipped Firefox fingerprint, hello2 is 656 bytes to hello1's 1880, the random and the
 * session id are CARRIED OVER, key_share drops from three entries (1216+32+65) to one, and every
 * byte after key_share — 339 of them, the whole ECH GREASE extension included — is IDENTICAL.
 * Nothing is re-drawn.
 *
 *   tools/fp/fp.exe retry -fp firefox -sni fp.example -group 0x0018 -o1 h1.bin -o2 h2.bin
 *
 * So the reference does not rebuild its hello; it mutates one field of the object it already has.
 * Splicing reproduces that by construction, which is the whole reason this is a splice and not a
 * second call to lc_hello_build: a rebuild would draw a fresh random, a fresh session id — which is
 * where REALITY's stamp lives — and fresh GREASE, and each of those would be a difference the
 * reference does not have. The first hello is already held to uTLS byte for byte by test/fphello;
 * transforming it the way uTLS transforms its own is what carries that guarantee to the second.
 *
 * Returns 0 and leaves the buffer holding the second message, with `info.slots` describing the one
 * key share the caller must now fill. */
/* Where the extension block of the hello being spliced begins and ends: the two-byte length field,
 * the first extension, and one past the last. Shared by the two splices below so that the walk over
 * session id, cipher suites and compression methods is written once — it is the part where an
 * off-by-one produces a hello that still parses and no longer matches. */
static int find_ext_block(const uint8_t *h, const lc_hello_out *info, size_t *len_at, size_t *start,
                          size_t *end)
{
    size_t total = info->len;

    size_t off = info->sid_off + info->sid_len;
    if (off + 2u > total)
        return -1;
    size_t cs = (size_t)h[off] << 8 | h[off + 1u];
    off += 2u + cs;
    if (off + 1u > total)
        return -1;
    off += 1u + h[off];                       /* legacy_compression_methods */
    if (off + 2u > total)
        return -1;
    *len_at = off;
    size_t ext_total = (size_t)h[off] << 8 | h[off + 1u];
    *start = off + 2u;
    *end = *start + ext_total;
    return *end > total ? -1 : 0;
}

/* ⚠️ THE COOKIE GOES AT A RANDOM INDEX, AND THAT IS THE REFERENCE'S RULE RATHER THAN A CHOICE MADE
 * HERE. This file used to refuse a retry carrying one, saying no capture existed of the position
 * the reference puts it in. Both halves of that turned out wrong on 2026-08-30.
 *
 * There is no position. When the fingerprint's extension list has no cookie of its own — none of
 * ours do — the reference INSERTS one at a random index:
 *
 *     cookieIndex := p.Intn(len(hs.uconn.Extensions) - 2)
 *     (vendor/utls/handshake_client_tls13.go:413-419, the -2 keeping PSK last)
 *
 * So a fixed position, however carefully reasoned, would have been the divergence. Matching means
 * drawing too. Measured with `fp retry -cookie` over twenty runs on the Firefox table: indices 0
 * through 11 with fifteen extensions, which is the [0, n-3] that draw produces and not a constant.
 *
 * The capture that was said not to exist is now made by the same tool that makes every other vector
 * here: `tools/fp` grew a -cookie flag, the synthetic HelloRetryRequest carries one, and the echo
 * comes back verbatim inside a hello2 whose every other byte is hello1's.
 *
 * Called BEFORE the key share is spliced, which is the opposite order from the reference and gives
 * the same wire: the reference mutates a list where order is all that exists, while here the offset
 * recorded in info.slots[0] would go stale if bytes were inserted ahead of it afterwards. */
int lc_hello_splice_cookie(uint8_t *h, size_t cap, lc_hello_out *info, const uint8_t *cookie,
                           size_t cookie_len)
{
    size_t total = info->len;

    size_t len_at, start, end;
    if (find_ext_block(h, info, &len_at, &start, &end) != 0)
        return -1;

    size_t n = 0;
    for (size_t off = start; off + 4u <= end;) {
        size_t len = (size_t)h[off + 2u] << 8 | h[off + 3u];
        if (off + 4u + len > end)
            return -1;
        off += 4u + len;
        n++;
    }
    if (n < 3u)
        return -1;

    size_t k;
    if (lc_rnd_below(n - 2u, &k) != 0)
        return -1;

    size_t ins = start;
    for (size_t i = 0; i < k; i++) {
        size_t len = (size_t)h[ins + 2u] << 8 | h[ins + 3u];
        ins += 4u + len;
    }

    size_t grown = 4u + 2u + cookie_len;
    /* An extension block past sixteen bits is a hello the reference cannot marshal: its builder
     * fails on the length prefix and the handshake ends on that error, with no alert of its own. */
    if ((end - start) + grown > 0xffffu)
        return -2;
    if (total + grown > cap)
        return -1;
    memmove(h + ins + grown, h + ins, total - ins);

    size_t at = ins;
    h[at++] = 0x00u;
    h[at++] = 0x2cu;
    h[at++] = (uint8_t)((cookie_len + 2u) >> 8);
    h[at++] = (uint8_t)(cookie_len + 2u);
    h[at++] = (uint8_t)(cookie_len >> 8);
    h[at++] = (uint8_t)cookie_len;
    memcpy(h + at, cookie, cookie_len);

    /* ⚠️ AND THE RECORDED KEY-SHARE OFFSETS MOVE WITH THE BYTES. Until the retry learned to
     * answer a cookie-only request this was carried by lc_hello_splice_key_share, which rebuilds slots[0]
     * from scratch a moment later — so nothing noticed that an insert ahead of a share leaves
     * info.slots pointing at the wrong place. On a retry that changes no group that rebuild never
     * happens, and the stale offset would be written through by whoever fills a public key next.
     * Fixed here rather than at the caller so the two splices stop depending on their order. */
    for (unsigned i = 0; i < info->slot_count; i++) {
        if (info->slots[i].off >= ins)
            info->slots[i].off += grown;
    }

    size_t new_ext_total = (end - start) + grown;
    h[len_at] = (uint8_t)(new_ext_total >> 8);
    h[len_at + 1u] = (uint8_t)new_ext_total;
    size_t msg_body = total + grown - 4u;
    h[1] = (uint8_t)(msg_body >> 16);
    h[2] = (uint8_t)(msg_body >> 8);
    h[3] = (uint8_t)msg_body;
    info->len = total + grown;
    return 0;
}

int lc_hello_splice_key_share(uint8_t *h, size_t cap, lc_hello_out *info, uint16_t group,
                              size_t key_len)
{
    size_t total = info->len;

    size_t ext_len_at, off, ext_end;
    if (find_ext_block(h, info, &ext_len_at, &off, &ext_end) != 0)
        return -1;
    size_t ext_total = ext_end - off;

    size_t ks_at = 0, ks_len = 0;
    int    found = 0;
    while (off + 4u <= ext_end) {
        size_t type = (size_t)h[off] << 8 | h[off + 1u];
        size_t len = (size_t)h[off + 2u] << 8 | h[off + 3u];
        if (off + 4u + len > ext_end)
            return -1;
        if (type == 0x0033u) {
            ks_at = off;
            ks_len = len;
            found = 1;
            break;
        }
        off += 4u + len;
    }
    if (!found)
        return -1;

    /* list length, group, key length, key. One entry, no GREASE beside it: RFC 8446 4.1.2. */
    size_t body = 2u + 2u + 2u + key_len;
    size_t tail_at = ks_at + 4u + ks_len;
    size_t tail_len = total - tail_at;
    size_t grown = 4u + body;
    if (ks_at + grown + tail_len > cap)
        return -1;

    memmove(h + ks_at + grown, h + tail_at, tail_len);
    size_t at = ks_at;
    h[at++] = 0x00u;
    h[at++] = 0x33u;
    h[at++] = (uint8_t)(body >> 8);
    h[at++] = (uint8_t)body;
    h[at++] = (uint8_t)((body - 2u) >> 8);
    h[at++] = (uint8_t)(body - 2u);
    h[at++] = (uint8_t)(group >> 8);
    h[at++] = (uint8_t)group;
    h[at++] = (uint8_t)(key_len >> 8);
    h[at++] = (uint8_t)key_len;
    memset(h + at, 0, key_len);

    size_t new_total = ks_at + grown + tail_len;
    size_t new_ext_total = ext_total + grown - (4u + ks_len);
    h[ext_len_at] = (uint8_t)(new_ext_total >> 8);
    h[ext_len_at + 1u] = (uint8_t)new_ext_total;
    /* The handshake header's 24-bit length, which counts everything after itself. */
    size_t msg_body = new_total - 4u;
    h[1] = (uint8_t)(msg_body >> 16);
    h[2] = (uint8_t)(msg_body >> 8);
    h[3] = (uint8_t)msg_body;

    info->len = new_total;
    info->slot_count = 1;
    info->slots[0].group = group;
    info->slots[0].off = at;
    info->slots[0].len = key_len;
    return 0;
}
