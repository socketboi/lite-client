/* ML-KEM-1024 — see tls/mlkem.h for who needs it.
 *
 * The same vendored sources as ML-KEM-768, compiled a second time at the other parameter set. The
 * library allows this in one of two ways: a multi-level build, where every copy is compiled with
 * MLK_CONFIG_MULTILEVEL_BUILD and exactly one keeps the shared (level-independent) code
 * (vendor/mlkem-native/mlkem/mlkem_native_config.h:70-87), or a single compilation unit per level
 * (vendor/mlkem-native/mlkem/mlkem_native.c:14-29). The first would change the name of every symbol
 * the 768 build already exports, and the flags of every rule in the Makefile that compiles it; the
 * second leaves them alone. So this is the second, with everything but the three entry points kept
 * inside this file: MLK_CONFIG_INTERNAL_API_QUALIFIER makes the library's internal functions static
 * (vendor/mlkem-native/mlkem/src/common.h:41-49), which is what keeps its copy of the Keccak and
 * polynomial code from colliding with the 768 build's at link time. The price is that copy, a few
 * kilobytes of flash.
 *
 * Randomness comes from `randombytes`, defined once in tls/mlkem.c. */
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_CONFIG_NAMESPACE_PREFIX
#define MLK_CONFIG_PARAMETER_SET 1024
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem1024
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static

/* Someone else's code, under our warnings. */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include "mlkem_native.c"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include "tls/mlkem.h"

int lc_mlkem1024_keygen(uint8_t ek[LC_MLKEM1024_EK], uint8_t dk[LC_MLKEM1024_DK])
{
    return mlkem1024_keypair(ek, dk) == 0 ? 0 : -1;
}

/* The seed is split into d and z the same way as at 768: see lc_mlkem_keygen_seed. */
int lc_mlkem1024_keygen_seed(const uint8_t seed[LC_MLKEM_SEED],
                             uint8_t ek[LC_MLKEM1024_EK], uint8_t dk[LC_MLKEM1024_DK])
{
    return mlkem1024_keypair_derand(ek, dk, seed) == 0 ? 0 : -1;
}

int lc_mlkem1024_decap(const uint8_t ct[LC_MLKEM1024_CT], const uint8_t dk[LC_MLKEM1024_DK],
                       uint8_t ss[LC_MLKEM_SS])
{
    return mlkem1024_dec(ss, ct, dk) == 0 ? 0 : -1;
}
