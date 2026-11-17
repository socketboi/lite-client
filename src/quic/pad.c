#include "quic/pad.h"

#include "core/rnd.h"

/* ⚠️ THIS FILE CITED NOTHING, AND EVERY LINE IN IT IS A COPY OF SOMEBODY ELSE'S DECISION — which
 * is the worst combination the sieve can be blind to. Padding is the whole of what makes a Hysteria
 * request look like the reference's; a wrong alphabet or a wrong range is invisible in testing and
 * plain to anyone counting bytes. The reference is twenty lines long and all of it matters:
 *
 *     paddingChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
 *                            (vendor/hysteria/core/internal/protocol/padding.go:8)
 *
 * — the same sixty-two characters as below, in the same order. The length is drawn `n := p.Min +
 * rand.Intn(p.Max-p.Min)` over a range the reference's own comment calls half-open
 * (vendor/hysteria/core/internal/protocol/padding.go:11-24), which is what lc_pad_draw does with
 * `max <= min` refused and `below(max - min)`. Each character is drawn separately — `bs[i] =
 * paddingChars[rand.Intn(len(paddingChars))]`
 * (vendor/hysteria/core/internal/protocol/padding.go:20-22) — and not as one draw stretched over
 * the string. The four ranges those are used with are at
 * vendor/hysteria/core/internal/protocol/padding.go:26-31.
 *
 * THE SOURCE OF THE NUMBERS IS NOT A DIVERGENCE, which this used to call it ("a weaker source" not
 * worth copying). The reference draws from math/rand's TOP-LEVEL functions, and with hysteria's
 * go.mod at go 1.25.0 — so GODEBUG randautoseed at its default — those run on runtimeSource, which
 * is runtime_rand: the runtime's ChaCha8 generator, seeded from the operating system
 * (GOROOT/src/math/rand/rand.go, globalRand and runtimeSource; GOROOT/src/runtime/rand.go). That
 * is a cryptographic source, as getrandom(2) here is. The weak one is Salamander's salt, which the
 * reference takes from a SEEDED lagged-Fibonacci generator and which does travel in the clear —
 * that one is copied, see quic/gorand.h. Both draws here are exactly uniform — Go's Int31n rejects
 * over 31 bits, `below` over 32, neither is biased — and the padding itself travels inside the
 * encrypted stream: what reaches the wire is its length, drawn from the same distribution.
 *
 * Spelled out rather than simplified to the lower-case letters: which characters appear decides how
 * well the padding Huffman-codes when it travels as a header value, and so decides the size of the
 * message. Padding drawn from a smaller alphabet would still be padding, and would still be the
 * wrong length. */
static const char pad_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* The draws are served from a pool one syscall refills, because on the MT7621 kernels this targets
 * getrandom(2) has no vDSO entry and every call traps into the kernel. A draw per character meant a
 * syscall per character, and the padding is not small: the Hysteria TCPRequest carries up to 512 of
 * them and it is built once per proxied TCP connection, so a router opening many short-lived
 * connections paid hundreds of trips into the kernel for each one before the connection could carry
 * a byte. The bytes are handed out four at a time in the order the kernel produced them, which is
 * the order a call per draw would have consumed them in, so the padding on the wire is unchanged. */
static uint8_t pool[256];
static size_t pool_next = sizeof pool; /* Starts empty, so the first draw refills. */

static int draw32(uint32_t *out)
{
    if (sizeof pool - pool_next < 4u) {
        if (lc_rnd(pool, sizeof pool) != 0)
            return -1;
        pool_next = 0;
    }
    const uint8_t *b = pool + pool_next;
    pool_next += 4u;
    *out = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
    return 0;
}

/* A number below `bound`, without the bias taking a remainder would introduce. The bias would be
 * small, and it would be a difference between this client and every other one — which is the kind
 * of small that matters here. */
static int below(uint32_t bound, uint32_t *out)
{
    uint32_t limit = UINT32_MAX - UINT32_MAX % bound;
    for (;;) {
        uint32_t v = 0;
        if (draw32(&v) != 0)
            return -1;
        if (v < limit) {
            *out = v % bound;
            return 0;
        }
    }
}

int lc_pad_draw(uint32_t min, uint32_t max, uint32_t *out)
{
    if (max <= min)
        return -1;
    uint32_t v = 0;
    if (below(max - min, &v) != 0)
        return -1;
    *out = min + v;
    return 0;
}

int lc_pad_fill(char *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        uint32_t k = 0;
        if (below(sizeof pad_chars - 1u, &k) != 0)
            return -1;
        out[i] = pad_chars[k];
    }
    return 0;
}
