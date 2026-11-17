/* mldsa.NewPublicKey and mldsa.Verify of Go 1.27.1 (GOROOT/src/crypto/mldsa and
 * GOROOT/src/crypto/internal/fips140/mldsa) — see cert/mldsa.h.
 *
 * The arithmetic is Go's own, Montgomery form included: every function below is the one it names,
 * with the same representation, so that a line here can be read against a line there. Where the
 * shape differs it is for memory only, and the difference is said where it is made: Go computes the
 * whole matrix A and every NTT(t1 * 2^d) before it looks at the signature (over 60 KiB for
 * ML-DSA-87); here they are computed a row at a time, as each row of w is. Nothing between Go's
 * first and last refusal can fail, so the order of the refusals — and therefore which one a bad
 * signature gets — is Go's.
 *
 * Nothing here is secret (see mldsa.h), so nothing is constant time: Go's constanttime selects are
 * written as plain comparisons with the same results. */
#include "cert/mldsa.h"

#include "tls/goerr.h"

/* The Keccak-f[1600] permutation of the vendored mlkem-native (the sponge is below), named after
 * MLK_CONFIG_NAMESPACE_PREFIX like every symbol of that library. */
#include "fips202/keccakf1600.h"

#include <string.h>

/* ---- the words --------------------------------------------------------------------------------- */

static int fail(lc_obuf *e, const char *text)
{
    if (e != NULL)
        lc_obuf_add(e, text, strlen(text));
    return -1;
}

/* ---- parameters -------------------------------------------------------------------------------- */

/* GOROOT/src/crypto/internal/fips140/mldsa/mldsa.go:17-31. gamma1 is log2(γ1); gamma2 is the
 * denominator of γ2 = (q - 1) / gamma2. */
typedef struct {
    unsigned k, l, eta, gamma1, gamma2, lambda, tau, omega;
} mldsa_params;

static const mldsa_params params44 = { 4, 4, 2, 17, 88, 128, 39, 80 };
static const mldsa_params params65 = { 6, 5, 4, 19, 32, 192, 49, 55 };
static const mldsa_params params87 = { 8, 7, 2, 19, 32, 256, 60, 75 };

#define N 256u
#define MAX_K 8u
#define MAX_L 7u

/* newPublicKey's switch (GOROOT/src/crypto/mldsa/mldsa_fips140v1.26.go:162-180). */
static const mldsa_params *params_of(int params)
{
    switch (params) {
    case LC_MLDSA_44: return &params44;
    case LC_MLDSA_65: return &params65;
    case LC_MLDSA_87: return &params87;
    default: return NULL;
    }
}

/* pubKeySize and sigSize (GOROOT/src/crypto/internal/fips140/mldsa/mldsa.go:33-41). */
static size_t pub_key_size(const mldsa_params *p)
{
    return 32u + p->k * N * 10u / 8u;
}

static size_t sig_size(const mldsa_params *p)
{
    return p->lambda / 4u + p->l * N * (p->gamma1 + 1u) / 8u + p->omega + p->k;
}

/* ---- SHAKE ------------------------------------------------------------------------------------- */

/* An incremental SHAKE128/256 — write any number of times, then read any number of bytes any number
 * of times, as Go's sha3.SHAKE is used here — on mlkem-native's permutation and its byte access to
 * the state. mlkem-native's own fips202.c has no such interface: its SHAKE256 is one call over one
 * buffer, and its SHAKE128 absorbs once and squeezes whole blocks. μ is taken over the caller's
 * message, which is not copied into one buffer with tr, and SampleInBall reads a byte at a time. */
typedef struct {
    uint64_t st[25];
    unsigned rate, pos;
    int      squeezing;
} shake;

#define SHAKE128_RATE_ 168u
#define SHAKE256_RATE_ 136u

static void shake_init(shake *h, unsigned rate)
{
    memset(h->st, 0, sizeof h->st);
    h->rate = rate;
    h->pos = 0;
    h->squeezing = 0;
}

static void shake_write(shake *h, const uint8_t *p, size_t n)
{
    while (n > 0u) {
        unsigned take = h->rate - h->pos;
        if ((size_t)take > n)
            take = (unsigned)n;
        mlk_keccakf1600_xor_bytes(h->st, p, h->pos, take);
        h->pos += take;
        p += take;
        n -= take;
        if (h->pos == h->rate) {
            mlk_keccakf1600_permute(h->st);
            h->pos = 0;
        }
    }
}

/* SHAKE's padding: the domain byte 0x1F, then the last bit of the block. */
static void shake_read(shake *h, uint8_t *out, size_t n)
{
    if (!h->squeezing) {
        uint8_t d = 0x1fu;
        mlk_keccakf1600_xor_bytes(h->st, &d, h->pos, 1u);
        d = 0x80u;
        mlk_keccakf1600_xor_bytes(h->st, &d, h->rate - 1u, 1u);
        mlk_keccakf1600_permute(h->st);
        h->pos = 0;
        h->squeezing = 1;
    }
    while (n > 0u) {
        if (h->pos == h->rate) {
            mlk_keccakf1600_permute(h->st);
            h->pos = 0;
        }
        unsigned take = h->rate - h->pos;
        if ((size_t)take > n)
            take = (unsigned)n;
        mlk_keccakf1600_extract_bytes(h->st, out, h->pos, take);
        h->pos += take;
        out += take;
        n -= take;
    }
}

/* ---- the field --------------------------------------------------------------------------------- */

/* GOROOT/src/crypto/internal/fips140/mldsa/field.go:14-21. */
#define Q 8380417u
#define RR 2365951u
#define Q_NEG_INV 4236238847u
#define ONE 4193792u
#define MINUS_ONE 4186625u

/* An element of Z_q in the Montgomery domain, in [0, q) (field.go:23-25). */
typedef uint32_t fe;

/* fieldReduceOnce (field.go:70-74), for a < 2q. */
static fe reduce_once(uint32_t a)
{
    return a >= Q ? a - Q : a;
}

/* fieldMontgomeryReduce (field.go:94-99), for x < q * 2^32. */
static fe mont_reduce(uint64_t x)
{
    uint32_t t = (uint32_t)x * Q_NEG_INV;
    uint64_t u = (x + (uint64_t)t * Q) >> 32;
    return reduce_once((uint32_t)u);
}

/* fieldMontgomeryMul (field.go:88-92). */
static fe mont_mul(fe a, fe b)
{
    return mont_reduce((uint64_t)a * b);
}

/* fieldMontgomeryMulSub (field.go:101-106): a * (b - c). */
static fe mont_mul_sub(fe a, fe b, fe c)
{
    return mont_reduce((uint64_t)a * (uint32_t)(b - c + Q));
}

/* fieldAdd and fieldSub (field.go:76-86). */
static fe field_add(fe a, fe b)
{
    return reduce_once(a + b);
}

static fe field_sub(fe a, fe b)
{
    return reduce_once(a - b + Q);
}

/* fieldToMontgomery (field.go:29-37) for a value already known to be < q; the one caller that does
 * not know it, sampleNTT, makes the check itself. */
static fe to_mont(uint32_t a)
{
    return mont_mul(a, RR);
}

/* fieldSubToMontgomery (field.go:39-44): a - b, for a and b < q. */
static fe sub_to_mont(uint32_t a, uint32_t b)
{
    return mont_mul(a - b + Q, RR);
}

/* fieldFromMontgomery (field.go:46-51). */
static uint32_t from_mont(fe a)
{
    return mont_reduce(a);
}

/* fieldInfinityNorm (field.go:61-68): |r| centred around 0. */
static uint32_t infinity_norm(fe r)
{
    int32_t x = (int32_t)from_mont(r);
    return (uint32_t)(x <= (int32_t)(Q / 2u) ? x : (int32_t)Q - x);
}

/* ---- NTT --------------------------------------------------------------------------------------- */

/* ζ^BitRev8(k) mod q in the Montgomery domain (field.go:140-142). */
static const uint32_t zetas[256] = {
    4193792, 25847,   5771523, 7861508, 237124,  7602457, 7504169, 466468,  1826347, 2353451, 8021166,
    6288512, 3119733, 5495562, 3111497, 2680103, 2725464, 1024112, 7300517, 3585928, 7830929, 7260833,
    2619752, 6271868, 6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005,  2706023,
    95776,   3077325, 3530437, 6718724, 4788269, 5842901, 3915439, 4519302, 5336701, 3574422, 5512770,
    3539968, 8079950, 2348700, 7841118, 6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997,
    3699596, 811944,  531354,  954230,  3881043, 3900724, 5823537, 2071892, 5582638, 4450022, 6851714,
    4702672, 5339162, 6927966, 3475950, 2176455, 6795196, 7122806, 1939314, 4296819, 7380215, 5190273,
    5223087, 4747489, 126922,  3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
    7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987, 5037034, 264944,  508951,
    3097992, 44288,   7280319, 904516,  3958618, 4656075, 8371839, 1653064, 5130689, 2389356, 8169440,
    759969,  7063561, 189548,  4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330, 1285669,
    6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961, 2091667, 3407706, 2316500, 3817976,
    5037939, 2244091, 5933984, 4817955, 266997,  2434439, 7144689, 3513181, 4860065, 4621053, 7183191,
    5187039, 900702,  1859098, 909542,  819034,  495491,  6767243, 8337157, 7857917, 7725090, 5257975,
    2031748, 3207046, 4823422, 7855319, 7611795, 4784579, 342297,  286988,  5942594, 4108315, 3437287,
    5038140, 1735879, 203044,  2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
    4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447, 7047359, 1237275, 5062207,
    6950192, 7929317, 1312455, 3306115, 6417775, 7100756, 1917081, 5834105, 7005614, 1500165, 777191,
    2235880, 3406031, 7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136,  4603424, 6366809,
    2432395, 2454455, 8215696, 1957272, 3369112, 185531,  7173032, 5196991, 162844,  1616392, 3014001,
    810149,  1652634, 4686184, 6581310, 5341501, 3523897, 3866901, 269760,  2213111, 7404533, 1717735,
    472078,  7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524, 5441381, 6144432,
    7959518, 6094090, 183443,  7403526, 1612842, 4834730, 7826001, 3919660, 8332111, 7018208, 3937738,
    1400424, 7534263, 1976782,
};

/* ntt (field.go:144-213), in place. Go unrolls len = 4, 2 and 1 and pairs of j; the butterflies and
 * their order are the same written as one loop. */
static void ntt(fe f[N])
{
    unsigned m = 0;
    for (unsigned len = 128; len >= 1u; len /= 2u) {
        for (unsigned start = 0; start < N; start += 2u * len) {
            m++;
            fe zeta = zetas[m];
            for (unsigned j = start; j < start + len; j++) {
                fe t = mont_mul(zeta, f[j + len]);
                f[j + len] = field_sub(f[j], t);
                f[j] = field_add(f[j], t);
            }
        }
    }
}

/* inverseNTT (field.go:215-288), in place; the unrolled len = 1, 2 and 4 of Go written as the same
 * loop as the rest. */
static void inverse_ntt(fe f[N])
{
    unsigned m = 255;
    for (unsigned len = 1; len < N; len *= 2u) {
        for (unsigned start = 0; start < N; start += 2u * len) {
            fe zeta = zetas[m];
            m--;
            for (unsigned j = start; j < start + len; j++) {
                fe t = f[j];
                f[j] = field_add(t, f[j + len]);
                /* -z * (t - f[j+len]) = z * (f[j+len] - t) */
                f[j + len] = mont_mul_sub(zeta, f[j + len], t);
            }
        }
    }
    for (unsigned i = 0; i < N; i++)
        f[i] = mont_mul(f[i], 16382u); /* 16382 = 256⁻¹ * R mod q */
}

/* ---- sampling ---------------------------------------------------------------------------------- */

/* sampleNTT (field.go:298-325): A[r][s] from ρ, s and r, by rejection from SHAKE128 in blocks of
 * its rate. Go's fieldToMontgomery refuses a value >= q, and the value is skipped. */
static void sample_ntt(const uint8_t rho[32], uint8_t s, uint8_t r, fe a[N])
{
    shake   g;
    uint8_t sr[2] = { s, r };
    shake_init(&g, SHAKE128_RATE_);
    shake_write(&g, rho, 32);
    shake_write(&g, sr, 2);

    uint8_t  buf[SHAKE128_RATE_];
    unsigned off = sizeof buf;
    unsigned j = 0;
    while (j < N) {
        if (off >= sizeof buf) {
            shake_read(&g, buf, sizeof buf);
            off = 0;
        }
        uint32_t v = (uint32_t)buf[off] | (uint32_t)buf[off + 1u] << 8 | (uint32_t)buf[off + 2u] << 16;
        off += 3u;
        v &= 0x7fffffu; /* 23 bits */
        if (v >= Q)
            continue;
        a[j++] = to_mont(v);
    }
}

/* sampleInBall (field.go:367-395): τ coefficients ±1, the rest 0, from c~. */
static void sample_in_ball(const uint8_t *rho, size_t rho_len, const mldsa_params *p, fe c[N])
{
    shake   h;
    uint8_t s[8];
    shake_init(&h, SHAKE256_RATE_);
    shake_write(&h, rho, rho_len);
    shake_read(&h, s, sizeof s);

    memset(c, 0, N * sizeof c[0]);
    for (unsigned i = N - p->tau; i < N; i++) {
        uint8_t j;
        shake_read(&h, &j, 1);
        while (j > i)
            shake_read(&h, &j, 1);
        c[i] = c[j];
        /* c[j] = (−1) ^ h[i+τ−256], the bits of s little-endian */
        unsigned bit_idx = i + p->tau - 256u;
        unsigned bit = (unsigned)(s[bit_idx / 8u] >> (bit_idx % 8u)) & 1u;
        c[j] = bit == 0u ? ONE : MINUS_ONE;
    }
}

/* ---- decoding ---------------------------------------------------------------------------------- */

/* One row of pkDecode (GOROOT/src/crypto/internal/fips140/mldsa/mldsa.go:279-296) and computeT1Hat
 * (mldsa.go:246-257): NTT(t1 * 2^d) of the r-th polynomial of the key. t1 <= 2^10 - 1, so
 * t1 * 2^13 < q and Go's fieldToMontgomery never refuses it. */
static void t1_hat_row(const uint8_t *pk, unsigned r, fe w[N])
{
    const uint8_t *b = pk + 32u + (size_t)r * (N * 10u / 8u);
    for (unsigned i = 0; i < N; i += 4u, b += 5) {
        uint32_t t0 = (uint32_t)b[0] | (uint32_t)(b[1] & 0x03u) << 8;
        uint32_t t1 = (uint32_t)(b[1] >> 2) | (uint32_t)(b[2] & 0x0fu) << 6;
        uint32_t t2 = (uint32_t)(b[2] >> 4) | (uint32_t)(b[3] & 0x3fu) << 4;
        uint32_t t3 = (uint32_t)(b[3] >> 6) | (uint32_t)b[4] << 2;
        w[i + 0u] = to_mont(t0 << 13);
        w[i + 1u] = to_mont(t1 << 13);
        w[i + 2u] = to_mont(t2 << 13);
        w[i + 3u] = to_mont(t3 << 13);
    }
    ntt(w);
}

/* bitUnpack (field.go:698-751): each γ1+1 bits little-endian into a coefficient in
 * [-2^γ1+1, 2^γ1], as 2^γ1 minus the value. */
static void bit_unpack(const uint8_t *v, const mldsa_params *p, fe r[N])
{
    if (p->gamma1 == 17u) {
        const uint32_t b = 1u << 17, mask18 = (1u << 18) - 1u;
        for (unsigned i = 0; i < N; i += 4u, v += 9) {
            uint32_t w0 = (uint32_t)v[0] | (uint32_t)v[1] << 8 | (uint32_t)v[2] << 16;
            r[i + 0u] = sub_to_mont(b, w0 & mask18);
            uint32_t w1 = (uint32_t)v[2] >> 2 | (uint32_t)v[3] << 6 | (uint32_t)v[4] << 14;
            r[i + 1u] = sub_to_mont(b, w1 & mask18);
            uint32_t w2 = (uint32_t)v[4] >> 4 | (uint32_t)v[5] << 4 | (uint32_t)v[6] << 12;
            r[i + 2u] = sub_to_mont(b, w2 & mask18);
            uint32_t w3 = (uint32_t)v[6] >> 6 | (uint32_t)v[7] << 2 | (uint32_t)v[8] << 10;
            r[i + 3u] = sub_to_mont(b, w3 & mask18);
        }
    } else {
        const uint32_t b = 1u << 19, mask20 = (1u << 20) - 1u;
        for (unsigned i = 0; i < N; i += 2u, v += 5) {
            uint32_t w0 = (uint32_t)v[0] | (uint32_t)v[1] << 8 | (uint32_t)v[2] << 16;
            r[i + 0u] = sub_to_mont(b, w0 & mask20);
            uint32_t w1 = (uint32_t)v[2] >> 4 | (uint32_t)v[3] << 4 | (uint32_t)v[4] << 12;
            r[i + 1u] = sub_to_mont(b, w1 & mask20);
        }
    }
}

/* hintDecode (GOROOT/src/crypto/internal/fips140/mldsa/mldsa.go:762-788). The length check at its
 * top ("internal error: invalid signature hint length") cannot fire: sigDecode has checked the
 * whole signature's length before it. Its three encoding refusals are three errors in Go with one
 * text (mldsa.go:628-630). */
static int hint_decode(const uint8_t *y, const mldsa_params *p, uint8_t h[MAX_K][N], lc_obuf *err)
{
    const unsigned omega = p->omega;
    unsigned       idx = 0; /* a byte in Go; it never passes ω <= 80 */
    for (unsigned i = 0; i < p->k; i++) {
        unsigned limit = y[omega + i];
        if (limit < idx || limit > omega)
            return fail(err, LC_GO("mldsa: invalid signature encoding"));
        unsigned first = idx;
        while (idx < limit) {
            if (idx > first && y[idx - 1u] >= y[idx])
                return fail(err, LC_GO("mldsa: invalid signature encoding"));
            h[i][y[idx]] = 1;
            idx++;
        }
    }
    for (unsigned i = idx; i < omega; i++) {
        if (y[i] != 0)
            return fail(err, LC_GO("mldsa: invalid signature encoding"));
    }
    return 0;
}

/* ---- hints ------------------------------------------------------------------------------------- */

/* highBits32 and decompose32 (field.go:519-543), for γ2 = (q - 1) / 32. */
static uint8_t high_bits32(uint32_t x)
{
    uint32_t r1 = (x + 127u) >> 7;
    r1 = (r1 * 1025u + (1u << 21)) >> 22;
    r1 &= 0x0fu;
    return (uint8_t)r1;
}

static uint8_t decompose32(fe r, int32_t *r0)
{
    uint32_t x = from_mont(r);
    uint8_t  r1 = high_bits32(x);
    /* r - r1 * (2 * γ2) mod± q */
    int32_t v = (int32_t)x - (int32_t)r1 * 2 * (int32_t)(Q - 1u) / 32;
    *r0 = (int32_t)(Q / 2u + 1u) <= v ? v - (int32_t)Q : v;
    return r1;
}

/* highBits88 and decompose88 (field.go:572-593), for γ2 = (q - 1) / 88. */
static uint8_t high_bits88(uint32_t x)
{
    uint32_t r1 = (x + 127u) >> 7;
    r1 = (r1 * 11275u + (1u << 23)) >> 24;
    r1 = r1 == 44u ? 0u : r1;
    return (uint8_t)r1;
}

static uint8_t decompose88(fe r, int32_t *r0)
{
    uint32_t x = from_mont(r);
    uint8_t  r1 = high_bits88(x);
    int32_t  v = (int32_t)x - (int32_t)r1 * 2 * (int32_t)(Q - 1u) / 88;
    *r0 = (int32_t)(Q / 2u + 1u) <= v ? v - (int32_t)Q : v;
    return r1;
}

/* useHint (field.go:480-498) with useHint32 (field.go:545-559) and useHint88 (field.go:595-617). */
static void use_hint(const fe r[N], const uint8_t h[N], const mldsa_params *p, uint8_t w[N])
{
    for (unsigned i = 0; i < N; i++) {
        int32_t r0;
        if (p->gamma2 == 32u) {
            uint8_t r1 = decompose32(r[i], &r0);
            if (h[i] == 1u) {
                if (r0 > 0)
                    r1 = (uint8_t)((r1 + 1u) % 16u);
                else
                    r1 = (uint8_t)((uint8_t)(r1 - 1u) % 16u); /* mod 256 first, as Go's byte */
            }
            w[i] = r1;
        } else {
            uint8_t r1 = decompose88(r[i], &r0);
            if (h[i] == 1u) {
                if (r0 > 0)
                    r1 = r1 == 43u ? 0u : (uint8_t)(r1 + 1u);
                else
                    r1 = r1 == 0u ? 43u : (uint8_t)(r1 - 1u);
            }
            w[i] = r1;
        }
    }
}

/* w1Encode (GOROOT/src/crypto/internal/fips140/mldsa/mldsa.go:560-588), written into H: four bits a
 * coefficient for γ2 = (q - 1) / 32, six for (q - 1) / 88. */
static void w1_encode(shake *h, const uint8_t w[N], const mldsa_params *p)
{
    uint8_t buf[6u * N / 8u];
    if (p->gamma2 == 32u) {
        for (unsigned i = 0; i < N; i += 2u)
            buf[i / 2u] = (uint8_t)(w[i] | w[i + 1u] << 4);
        shake_write(h, buf, 4u * N / 8u);
    } else {
        for (unsigned i = 0; i < N; i += 4u) {
            uint8_t b0 = w[i], b1 = w[i + 1u], b2 = w[i + 2u], b3 = w[i + 3u];
            buf[3u * i / 4u + 0u] = (uint8_t)(b0 >> 0 | b1 << 6);
            buf[3u * i / 4u + 1u] = (uint8_t)(b1 >> 2 | b2 << 4);
            buf[3u * i / 4u + 2u] = (uint8_t)(b2 >> 4 | b3 << 2);
        }
        shake_write(h, buf, 6u * N / 8u);
    }
}

/* ---- the two calls ----------------------------------------------------------------------------- */

int lc_mldsa_public_key_ok(int params, const uint8_t *pk, size_t len, lc_obuf *err)
{
    (void)pk;
    /* newPublicKey (GOROOT/src/crypto/mldsa/mldsa_fips140v1.26.go:162-180): a parameter set it does
     * not know is errInvalidParameters (mldsa_fips140v1.26.go:24) ... */
    const mldsa_params *p = params_of(params);
    if (p == NULL)
        return fail(err, LC_GO("mldsa: invalid parameters"));
    /* ... and the internal newPublicKey (GOROOT/src/crypto/internal/fips140/mldsa/mldsa.go:312-329)
     * judges the length and nothing else (errInvalidPublicKeyLength, mldsa.go:298). */
    if (len != pub_key_size(p))
        return fail(err, LC_GO("mldsa: invalid public key length"));
    return 0;
}

int lc_mldsa_verify(int params, const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                    const uint8_t *sig, size_t sig_len, lc_obuf *err)
{
    /* The public Verify's own refusals — a nil key and the zero PublicKey
     * (GOROOT/src/crypto/mldsa/mldsa_fips140v1.26.go:215-226) — are for a key NewPublicKey did not
     * make, and every key here is one it made. opts is nil, so the context is empty and
     * errContextTooLong cannot fire. */
    if (lc_mldsa_public_key_ok(params, pk, pk_len, err) != 0)
        return -1;
    const mldsa_params *p = params_of(params);

    /* tr = H(pk, 64), computePublicKeyHash (mldsa.go:238-244), which NewPublicKey stores; and
     * μ = H(tr || 0 || |ctx| || ctx || msg, 64), computeMessageHash (mldsa.go:406-419) with an
     * empty context. Both are GOROOT/src/crypto/internal/fips140/mldsa/mldsa.go. */
    shake   h;
    uint8_t tr[64], mu[64];
    shake_init(&h, SHAKE256_RATE_);
    shake_write(&h, pk, pk_len);
    shake_read(&h, tr, sizeof tr);
    static const uint8_t domain_and_ctx_len[2] = { 0, 0 };
    shake_init(&h, SHAKE256_RATE_);
    shake_write(&h, tr, sizeof tr);
    shake_write(&h, domain_and_ctx_len, sizeof domain_and_ctx_len);
    shake_write(&h, msg, msg_len);
    shake_read(&h, mu, sizeof mu);

    /* verifyInternal (mldsa.go:652-718). pkDecode cannot fail on a key NewPublicKey took, and A and
     * NTT(t1 * 2^d) are computed row by row below instead of here (see the top of this file). */
    const unsigned k = p->k, l = p->l;
    const uint32_t beta = p->tau * p->eta;
    const uint32_t gamma1_beta = (1u << p->gamma1) - beta;

    /* sigDecode (mldsa.go:730-744): the length first, then z, then the hints — the only refusals
     * it has. */
    if (sig_len != sig_size(p))
        return fail(err, LC_GO("mldsa: invalid signature length"));
    const uint8_t *ch = sig;
    const size_t   ch_len = p->lambda / 4u;
    const size_t   z_len = (p->gamma1 + 1u) * N / 8u;

    fe      z_hat[MAX_L][N];
    uint8_t hints[MAX_K][N];
    memset(hints, 0, sizeof hints);
    for (unsigned i = 0; i < l; i++)
        bit_unpack(sig + ch_len + i * z_len, p, z_hat[i]);
    if (hint_decode(sig + ch_len + l * z_len, p, hints, err) != 0)
        return -1;

    /* The bound on z (mldsa.go:707-711) is Go's to check after w, and it is checked there below;
     * it is taken now because z is about to become NTT(z) in place. coefficientsExceedBound
     * (mldsa.go:590-600): ||z||∞ ≥ γ1 − β. */
    int z_exceeds = 0;
    for (unsigned i = 0; i < l && !z_exceeds; i++) {
        for (unsigned j = 0; j < N; j++) {
            if (infinity_norm(z_hat[i][j]) >= gamma1_beta) {
                z_exceeds = 1;
                break;
            }
        }
    }

    /* c = NTT(SampleInBall(c~)) (mldsa.go:676) and NTT(z) (mldsa.go:679-682). */
    fe c_hat[N];
    sample_in_ball(ch, ch_len, p, c_hat);
    ntt(c_hat);
    for (unsigned i = 0; i < l; i++)
        ntt(z_hat[i]);

    /* H(μ || w1Encode(w1[0]) || ... , λ/4) (mldsa.go:699-705), fed a row at a time. */
    shake_init(&h, SHAKE256_RATE_);
    shake_write(&h, mu, sizeof mu);

    const uint8_t *rho = pk;
    fe             a[N], t1_hat[N], w[N];
    uint8_t        w1[N];
    for (unsigned i = 0; i < k; i++) {
        /* w = Â ∘ NTT(z) − NTT(c) ∘ NTT(t₁ ⋅ 2ᵈ) (mldsa.go:678-691), with A[i][j] from
         * computeMatrixA (mldsa.go:229-236) as sampleNTT(ρ, j, i). */
        memset(w, 0, sizeof w);
        for (unsigned j = 0; j < l; j++) {
            sample_ntt(rho, (uint8_t)j, (uint8_t)i, a);
            for (unsigned m = 0; m < N; m++)
                w[m] = field_add(w[m], mont_mul(a[m], z_hat[j][m]));
        }
        t1_hat_row(pk, i, t1_hat);
        for (unsigned m = 0; m < N; m++)
            w[m] = field_sub(w[m], mont_mul(c_hat[m], t1_hat[m]));
        inverse_ntt(w);

        /* w1 = UseHint(h, w) (mldsa.go:693-697), then into H. */
        use_hint(w, hints[i], p, w1);
        w1_encode(&h, w1, p);
    }
    uint8_t computed_ch[256u / 4u];
    shake_read(&h, computed_ch, ch_len);

    /* The two refusals of a well-formed signature, in Go's order (mldsa.go:707-715):
     * errInvalidSignatureCoeffBounds, then errInvalidSignatureChallenge — two errors with one text
     * (mldsa.go:626-627). */
    if (z_exceeds)
        return fail(err, LC_GO("mldsa: invalid signature"));
    if (memcmp(ch, computed_ch, ch_len) != 0)
        return fail(err, LC_GO("mldsa: invalid signature"));
    return 0;
}
