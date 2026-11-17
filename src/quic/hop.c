/* WHICH PORT FROM THE RANGE — ONE WRITING, because both the first dial and every hop ask it and a
 * rule written twice is two rules. It stood twice inside conn.c, in two shapes, and the two had
 * already begun to drift.
 *
 * Drawn afresh and UNIFORMLY on every call, which is what the reference does: `rand.Intn(len(addrs))`
 * for the first dial (vendor/hysteria/extras/transport/udphop/conn.go:89) and
 * `u.addrIndex = rand.Intn(len(u.Addrs))` for each hop (:216-218); Xray's own hopping, a finalmask
 * since v26.9.9, draws the same way
 * (vendor/Xray-core/transport/internet/finalmask/udphop/conn.go:105). Not a walk up the range —
 * upstream does not walk one, and a walk is as recognisable as standing still.
 *
 * ⚠️ UNIFORMLY IS NOT `r % span`, which is what both sites did. A modulus over a 32-bit draw favours
 * the low end of the range and `rand.Intn` does not — Go rejects the last incomplete block rather
 * than folding it in. The skew is far too small to see on the wire, and that is precisely why it
 * survived in two places for as long as it did; but the reference's distribution is part of the
 * reference, and this client's whole claim is that there is nothing to tell apart.
 * `(uint32_t)(0u - span) % span` is 2^32 mod span, the size of that incomplete block; drawing again
 * while below it is Go's rejection written in C. It cannot loop forever: `reject` is strictly below
 * span and span is at most 65536, so all but a vanishing fraction of the 2^32 draws leave it.
 *
 * ⚠️ THE ARITHMETIC IS 32-BIT ON PURPOSE. What this replaced computed the span as
 * `(uint16_t)(hi - lo + 1u)`, which for lo=0, hi=65535 truncates to zero — and a span of zero is a
 * modulus by zero. Here the same inputs give 65536 and the worst outcome is a port outside the
 * caller's intent rather than a dead process.
 *
 * ⚠️ A FAILED DRAW IS NOT A ZERO. Both sites this replaced called lc_rnd and dropped its result, so
 * a source that could not deliver left `r` at zero and the port at `lo` — the bottom of the range,
 * every time, chosen predictably and silently. core/rnd.h says what to do instead in as many words:
 * "bytes, or an error the caller must handle", because a proxy that quietly degrades to a weaker
 * source produces traffic that looks fine and is not. So the error comes back, and the two callers
 * do with it what they already do with a dial that did not work. */

#include "quic/hop.h"

#include "core/rnd.h"


int lc_hop_port(uint16_t lo, uint16_t hi, uint16_t *out)
{
    uint32_t span = (uint32_t)hi - (uint32_t)lo + 1u;
    uint32_t reject = (uint32_t)(0u - span) % span;
    uint32_t r = 0;
    do {
        if (lc_rnd((uint8_t *)&r, sizeof r) != 0)
            return -1;
    } while (r < reject);
    *out = (uint16_t)(lo + r % span);
    return 0;
}

/* See hop.h. The reference's two halves: setDF runs when the conn offers SyscallConn
 * (vendor/quic-go/sys_conn.go:56-73), the hop conn offers its CURRENT socket's
 * (vendor/hysteria/extras/transport/udphop/conn.go:337-345), and hop() moves buffers and deadlines to
 * the new socket, not DF (vendor/hysteria/extras/transport/udphop/conn.go:172-225). */
int lc_hop_sets_df(int hopping, int first_socket)
{
    return !hopping || first_socket;
}
