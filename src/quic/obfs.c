#include "quic/obfs.h"

#include "core/blake2b.h"
#include "core/wipe.h"

#include <string.h>
#include <time.h>

#define KEY_LEN 32u

int lc_obfs_init(lc_obfs *o, const char *password)
{
    memset(o, 0, sizeof *o);
    if (password == NULL || password[0] == '\0')
        return 0;

    size_t len = strlen(password);
    /* Four is Hysteria's own floor. Refused rather than accepted quietly, because a password the
     * server will not take produces the same silence as no obfuscation at all. */
    if (len < 4u || len > sizeof o->password)
        return -1;

    memcpy(o->password, password, len);
    o->password_len = len;
    o->on = 1;

    /* time.Now().UnixNano(), which is what the reference seeds its salt source with, once per
     * obfuscated connection (vendor/hysteria/extras/obfs/salamander.go:43; the connection is made in
     * wrapObfs, vendor/hysteria/app/cmd/client.go:335-342, as this is called from lc_qconn_open). */
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    lc_gorand_seed(&o->salt, (int64_t)now.tv_sec * 1000000000 + (int64_t)now.tv_nsec);
    return 0;
}

/* The key stream for one packet. Derived per packet from its own salt, which is what stops the same
 * mask covering two packets — with a fixed mask, two packets XORed together would give away their
 * plaintext difference. */
static int keystream(const lc_obfs *o, const uint8_t *salt, uint8_t key[KEY_LEN])
{
    uint8_t input[sizeof o->password + LC_OBFS_SALT];
    memcpy(input, o->password, o->password_len);
    memcpy(input + o->password_len, salt, LC_OBFS_SALT);
    int rc = lc_blake2b(input, o->password_len + LC_OBFS_SALT, key, KEY_LEN);
    /* The obfuscation password in clear, and this frame is called once per packet — so whatever is
     * left here is left in the frame the very next packet reuses. It was not wiped at all: the two
     * derived buffers below were, and the one holding the password itself was not. */
    lc_wipe(input, sizeof input);
    return rc;
}

long lc_obfs_wrap(lc_obfs *o, const uint8_t *in, size_t len, uint8_t *out, size_t out_cap)
{
    if (!o->on) {
        if (len > out_cap)
            return -1;
        memcpy(out, in, len);
        return (long)len;
    }

    if (len + LC_OBFS_SALT > out_cap)
        return -1;
    /* ⚠️ THE REFERENCE'S SALT, FROM THE REFERENCE'S GENERATOR — math/rand, not the kernel.
     *
     * salamanderObfuscator draws every salt with `o.RandSrc.Read(out[:smSaltLen])` from
     * `rand.New(rand.NewSource(time.Now().UnixNano()))` (vendor/hysteria/extras/obfs/salamander.go:
     * 43, :65), and so does this, through the port in quic/gorand.c, seeded in lc_obfs_init.
     *
     * The salt is on the wire in the clear, so its generator is something a path can see. The
     * reference's is predictable — Seed keeps only `seed % int32max`, so one of 2^31 streams, and
     * an observer holding a few salts can recover which and check the rest — and that is part of
     * what a hysteria client looks like. This matches it, weakness included.
     *
     * ⛔ UNTIL 2026-09-23 THIS TOOK lc_rnd AND CALLED THAT DELIBERATE, on the argument that a
     * predictable salt makes the per-packet key predictable. It does not: the salt is sent in the
     * clear either way, the key is BLAKE2b-256 of the PASSWORD and the salt, and a mask repeats only
     * if a salt repeats, which a generator with this period does not do. No user decision stood
     * behind it. It also cost a getrandom(2) on every datagram — 2 % of the process on the
     * AX3000T, profiled on an upload. */
    lc_gorand_read(&o->salt, out, LC_OBFS_SALT);

    uint8_t key[KEY_LEN];
    if (keystream(o, out, key) != 0)
        return -1;

    for (size_t i = 0; i < len; i++)
        out[LC_OBFS_SALT + i] = in[i] ^ key[i % KEY_LEN];

    lc_wipe(key, sizeof key);
    return (long)(len + LC_OBFS_SALT);
}

long lc_obfs_unwrap(const lc_obfs *o, const uint8_t *in, size_t len, uint8_t *out, size_t out_cap)
{
    if (!o->on) {
        if (len > out_cap)
            return -1;
        memcpy(out, in, len);
        return (long)len;
    }

    /* Not `<`: a datagram of exactly the salt length carries no body, and the reference refuses it.
     * salamanderObfuscator.Deobfuscate computes `outLen := len(in) - smSaltLen` and returns 0 for
     * `outLen <= 0` (vendor/hysteria/extras/obfs/salamander.go:74-78, smSaltLen = 8), so eight bytes
     * in means rejected there and an empty payload accepted here. This is the only length check the
     * obfuscation layer performs — XOR with a key derived from a salt the sender picks cannot tell a
     * wrong password from a right one — so the one number it does refuse should be the same number. */
    if (len <= LC_OBFS_SALT)
        return -1;

    size_t body = len - LC_OBFS_SALT;
    if (body > out_cap)
        return -1;

    uint8_t key[KEY_LEN];
    if (keystream(o, in, key) != 0)
        return -1;

    for (size_t i = 0; i < body; i++)
        out[i] = in[LC_OBFS_SALT + i] ^ key[i % KEY_LEN];

    lc_wipe(key, sizeof key);
    return (long)body;
}
