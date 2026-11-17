/* Reading a packed fingerprint table.
 *
 * The table arrives from the API and describes, field by field, the ClientHello this client must
 * produce. Format is documented in tools/fp/pack.go, which is the only thing that writes it.
 *
 * Nothing is copied out and nothing is allocated: a cursor walks the blob, and the hello builder
 * reads it as it emits. The table is walked twice — once to size the message, once to write it —
 * which is cheaper than holding a parsed copy on a device with this much RAM.
 *
 * Every read is bounds-checked and sets a sticky error. A table that does not parse is refused
 * whole: there is no partial acceptance, because a table missing one extension yields a hello that
 * connects perfectly and is uniquely identifiable. */
#ifndef LC_FPT_H
#define LC_FPT_H

#include <stddef.h>
#include <stdint.h>

/* Modes, mirroring tools/fp/pack.go. */
#define LC_FPT_LITERAL        1
#define LC_FPT_SNI            2
#define LC_FPT_KEY_SHARE      3
#define LC_FPT_RANDOM_PAYLOAD 4
#define LC_FPT_PADDING        5
#define LC_FPT_ECH_GREASE     6
/* quic_transport_parameters, whose body is the QUIC transport's and not the table's: it is handed to
 * lc_hello_build_quic with the server name. Only the Hysteria2 plane's table carries it, and a
 * REALITY table that did would be one no caller of lc_hello_build can honour — which is why it is
 * NOT in lc_fpt_caps, and a table asking for it is refused there like any mode this build lacks. */
#define LC_FPT_QUIC_PARAMS    7

/* ✅ THE GREASE-ECH CANDIDATES NOW COME FROM THE TABLE, WHERE THEY BELONG.
 *
 * uTLS picks the HPKE suite at RANDOM for every ClientHello — `rndIndex` over
 * CandidateCipherSuites (vendor/utls/u_ech.go:95-107) — out of a list the PARROT defines
 * (u_parrots.go:1533, 1656). Two constants stood here instead, and the note beside them admitted
 * why: "the candidate list is a property of the fingerprint and belongs in the table; until the
 * format carries it, the pair is here."
 *
 * The format carries it now. The objection that kept it in code was that a table is derived from
 * one capture and a capture shows one draw — true of a capture, false of how this table is
 * actually made: tools/fp drives uTLS itself (`BuildHandshakeState`), so it holds the parrot and
 * can read the list off it rather than off the rendered bytes. Reading data from the source of the
 * data is not the same as typing the data in.
 *
 * The record is `kdf(u16) count(u8) aead[count](u16) enc_len(u16) count(u8) payload[count](u16)`,
 * the payload lengths PRE-encryption and drawn per hello like the suite (u_ech.go:160-166), each
 * growing by the AEAD's 16-byte tag on the wire (u_hpke.go:29-36). A count of zero in either list is
 * REFUSED rather than filled in: uTLS with an empty list makes a choice of its own (u_ech.go:95-98,
 * 131-133), which this client cannot reproduce faithfully, and a table asking for behaviour we
 * cannot copy is a table to reject loudly. */
#define LC_FPT_ECH_MAX_AEADS 8u
#define LC_FPT_ECH_MAX_LENS  8u

/* Bits of the flags byte that follows a table's name. */
#define LC_FPT_FLAG_KEY_SHARE_REUSE 0x01u

/* The value GREASE is stored as. Any occurrence must be replaced by a freshly drawn one. */
#define LC_FPT_GREASE 0x0a0au

/* The most key share groups a table may ask for. Four is the widest a real fingerprint uses — a
 * hybrid, its classical half, a second curve and a GREASE slot — and a table asking for more is
 * refused rather than truncated. */
#define LC_FPT_MAX_GROUPS 8u

/* What a table needs of whoever builds it, read from its header before anything else.
 *
 * This exists because the two ways a fingerprint can outgrow a client are not alike. A browser that
 * adds an extension almost always adds fixed bytes, which any build emits as a literal — nothing
 * here changes. A browser that adds a key exchange group is a different matter: a key share must be
 * a real public key, so no table format can carry one and no client can improvise it. Reading the
 * requirement first turns that from a failure discovered on a router into a fact the API can act on
 * before sending the table at all. */
typedef struct {
    uint32_t modes; /* bit per LC_FPT_* mode number */
    uint16_t groups[LC_FPT_MAX_GROUPS];
    unsigned group_count;
} lc_fpt_needs;

typedef struct {
    const uint8_t *p;
    size_t         len;
    size_t         off;
    int            err; /* set once a read ran past the end; never cleared */
} lc_fpt;

/* Validates magic and version, reads the requirement block, and positions the cursor at the name
 * field. `needs` may be NULL when the caller has already checked them.
 * Returns 0 on success, -1 if this is not a table this build can read. */
int lc_fpt_open(lc_fpt *c, const uint8_t *blob, size_t len, lc_fpt_needs *needs);

/* What this build can actually produce. Compared against a table's requirements by
 * lc_fpt_supported, and worth exposing on its own so a client can report it. */
void lc_fpt_caps(lc_fpt_needs *out);

/* Returns 0 when this build can produce the table. Otherwise -1, with `why` naming the first gap —
 * the specific mode or the specific group, because "unsupported table" is not something anyone can
 * act on. */
int lc_fpt_supported(const uint8_t *blob, size_t len, char *why, size_t why_cap);

/* The same question from a caller that brings more than lc_fpt_caps promises: `extra_modes` is the
 * bit set of LC_FPT_* modes it supplies itself — LC_FPT_QUIC_PARAMS for lc_hello_build_quic. */
int lc_fpt_supported_with(const uint8_t *blob, size_t len, uint32_t extra_modes, char *why,
                          size_t why_cap);

/* Moves the cursor to a byte the caller has already walked past.
 *
 * The format is a stream and the two passes read it forward, so this exists for exactly one job:
 * the Chrome extension shuffle emits the extension records in an order that is not the table's, and
 * an offset noted during the sizing pass is the only handle on a record that is not next. An offset
 * outside the blob sets the sticky error rather than moving, so a bad seek fails the walk the same
 * way a short read does. */
void lc_fpt_seek(lc_fpt *c, size_t off);

/* Where the cursor stands, so a caller can come back to it. */
size_t lc_fpt_tell(const lc_fpt *c);

uint8_t        lc_fpt_u8(lc_fpt *c);
uint16_t       lc_fpt_u16(lc_fpt *c);
const uint8_t *lc_fpt_bytes(lc_fpt *c, size_t n);

/* True once the cursor has run past the end. Checked once after a full walk. */
int lc_fpt_failed(const lc_fpt *c);

#endif
