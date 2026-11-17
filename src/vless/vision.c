#include "vless/vision.h"

#include "core/rnd.h"

#include <string.h>

/* Padding sizes, from Xray's defaults. While the inner handshake is in flight a short payload is
 * padded up to roughly 900-1400 bytes; afterwards padding is a small random tail. The numbers are
 * not arbitrary — they are what makes a Vision stream look like ordinary TLS records rather than
 * like a proxy passing small frames back and forth. */
#define PAD_LONG_THRESHOLD 900u
#define PAD_LONG_RANGE 500u
#define PAD_LONG_BASE 900u
#define PAD_SHORT_RANGE 256u

/* An outgoing frame never exceeds one buffer's worth of payload. 21 is the largest header this
 * format writes: sixteen bytes of UUID plus the five-byte padding header.
 *
 * 8192, not 16384: every Vision bound in the reference is measured from `buf.Size`
 * (vendor/Xray-core/common/buf/buffer.go:13, `Size = 8192`), which is the size of the buffer
 * XtlsPadding is handed. A record's worth of plaintext is the TLS limit, not this format's, and
 * using it let a frame reach twice anything the reference can produce. */
#define MAX_FRAME 8192u
#define MAX_HEADER 21u

/* The two bounds vision.h publishes, tied to the constants above so that changing padding here
 * cannot silently shrink the room the tunnel reserves for it. A frame that outgrows the reserve is
 * a queue push that fails, which is an established session torn down mid-transfer. */
_Static_assert(LC_VISION_MAX_BODY == MAX_FRAME - MAX_HEADER,
               "the published body bound must be what lc_vision_pad actually caps at");
_Static_assert(LC_VISION_MAX_LONG == PAD_LONG_BASE + PAD_LONG_RANGE - 1u,
               "the published long-padding bound must be the largest target it can pick");

/* The first bytes of the handshake records that carry ServerHello and ClientHello. Recognising
 * these is the whole of the filter. */
static const uint8_t tls_server_handshake_start[3] = { 0x16, 0x03, 0x03 };
static const uint8_t tls_client_handshake_start[2] = { 0x16, 0x03 };
/* Six bytes, not four: vendor/Xray-core/proxy/proxy.go:38 is
 * `Tls13SupportedVersions = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}` — the extension header AND
 * the version it carries. Truncating it to the header alone matched any supported_versions holding
 * exactly one version, TLS 1.2 included, and did so 65536 times more often by accident. */
static const uint8_t tls13_supported_versions[6] = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };

void lc_vision_init(lc_vision *v, const uint8_t uuid[LC_VLESS_UUID])
{
    memset(v, 0, sizeof *v);
    memcpy(v->uuid, uuid, LC_VLESS_UUID);
    v->padding_out = 1;
    v->packets_to_filter = LC_VISION_FILTER_PACKETS;
    v->remaining_command = -1;
    v->remaining_content = -1;
    v->remaining_padding = -1;
    v->within_padding = 1;
    /* -1, as `RemainingServerHello: -1` (vendor/Xray-core/proxy/proxy.go:150). Nothing reads it
     * until a ServerHello sets it and every test is `> 0`, so 0 behaved the same; the state is the
     * reference's anyway, because test/vision compares it field by field. */
    v->remaining_server_hello = -1;
}

/* A value in [0, bound), UNIFORMLY, because the reference's is: `rand.Int(rand.Reader,
 * big.NewInt(int64(testseed[1])))` (vendor/Xray-core/proxy/proxy.go:508, :514) rejects rather than
 * reduces. This took four bytes modulo the bound, which for 500 leans 296 of 2^32 values towards the
 * low end — invisible in any one frame and a lean all the same, and the tree already has the
 * unbiased draw the hello uses. */
static int rand_below(uint32_t bound, uint32_t *out)
{
    size_t v = 0;
    if (lc_rnd_below(bound, &v) != 0)
        return -1;
    *out = (uint32_t)v;
    return 0;
}

int lc_vision_pad(lc_vision *v, uint8_t command, int long_padding,
                  const uint8_t *payload, size_t payload_len,
                  uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (payload_len > MAX_FRAME - MAX_HEADER)
        return -1;

    uint32_t pad = 0;
    if (payload_len < PAD_LONG_THRESHOLD && long_padding) {
        uint32_t r = 0;
        if (rand_below(PAD_LONG_RANGE, &r) != 0)
            return -1;
        /* Long padding brings the frame up to roughly a kilobyte regardless of how little is in it,
         * which is what hides the VLESS header sitting in the first one. */
        uint32_t target = r + PAD_LONG_BASE;
        pad = target > payload_len ? target - (uint32_t)payload_len : 0;
    } else {
        if (rand_below(PAD_SHORT_RANGE, &pad) != 0)
            return -1;
    }
    if (pad + payload_len > MAX_FRAME - MAX_HEADER)
        pad = (uint32_t)(MAX_FRAME - MAX_HEADER - payload_len);

    size_t uuid_len = v->uuid_sent ? 0u : LC_VLESS_UUID;
    size_t need = uuid_len + LC_VISION_HEADER + payload_len + pad;
    if (need > out_cap)
        return -1;

    size_t i = 0;
    if (uuid_len > 0) {
        /* Once per direction, and only on the first padded frame. Sending it twice would be a
         * different stream shape and a different fingerprint. */
        memcpy(out, v->uuid, LC_VLESS_UUID);
        i += LC_VLESS_UUID;
        v->uuid_sent = 1;
    }

    out[i++] = command;
    out[i++] = (uint8_t)(payload_len >> 8);
    out[i++] = (uint8_t)payload_len;
    out[i++] = (uint8_t)(pad >> 8);
    out[i++] = (uint8_t)pad;

    if (payload_len > 0) {
        memcpy(out + i, payload, payload_len);
        i += payload_len;
    }
    memset(out + i, 0, pad);
    i += pad;

    *out_len = i;
    return 0;
}

/* How much one read of the peer's stream can return, which is where the reference's unpadder sees a
 * buffer begin and end. The Vision reader on the downlink reads through a SingleReader over the
 * REALITY connection — what buf.NewReader builds from a connection that is no syscall.Conn
 * (vendor/Xray-core/common/buf/io.go:113-145) — and each of its reads is one Read into a fresh
 * `buf.Size` buffer (vendor/Xray-core/common/buf/reader.go:28-36, :157-160). The connection's Read
 * hands back what is left of the current record and never reaches into the next
 * (vendor/utls/u_conn.go:874-885). So a read is at most 8192 bytes, and never crosses a record. */
#define READ_SIZE 8192u

/* THE PEER'S UUID IS LOOKED FOR IN EVERY BUFFER THAT ARRIVES IN THE STARTING STATE, AND ONLY IN ONE
 * THAT HOLDS ALL OF IT AND A HEADER. XtlsUnpadding, for one buffer
 * (vendor/Xray-core/proxy/proxy.go:539-621): in the starting state — all three counters -1 — a
 * buffer of at least 21 bytes that opens with the UUID starts a block, and any other buffer is
 * returned as it stands. Only the counters and the command carry over to the next buffer. So:
 *
 *   - a UUID cut by a record boundary is not a UUID. Both halves pass as payload. Until 2026-09-24
 *     this held the bytes across reads until sixteen had arrived — an answer the reference never
 *     gives, and the difference is the whole stream: framed here, raw there;
 *   - a peer that does not frame is not concluded to be unframed. Every later buffer that arrives
 *     while the state is still the starting one is tested again. This used to latch "not Vision"
 *     after the first miss, on the argument that a payload opening with the account's UUID would be
 *     misread — true, and the reference's behaviour all the same;
 *   - a command the format does not define is a block like any other: its content comes out, its
 *     padding is skipped, and the state goes back to the start. This used to end the connection.
 *
 * `out` has room for `len` bytes; nothing here writes more than it consumes. */
static size_t unpad_buffer(lc_vision *v, const uint8_t *b, size_t len, uint8_t *out)
{
    size_t off = 0, n = 0;

    if (v->remaining_command == -1 && v->remaining_content == -1 && v->remaining_padding == -1) {
        /* Constant time, as everywhere else this file's neighbours compare a credential: the branch
         * only picks a framing mode, but the bytes are still the account's UUID. */
        uint8_t diff = 1;
        if (len >= LC_VLESS_UUID + LC_VISION_HEADER) {
            diff = 0;
            for (size_t i = 0; i < LC_VLESS_UUID; i++)
                diff = (uint8_t)(diff | (b[i] ^ v->uuid[i]));
        }
        if (diff != 0) {
            memcpy(out, b, len);
            return len;
        }
        off = LC_VLESS_UUID;
        v->remaining_command = 5;
    }

    while (off < len) {
        if (v->remaining_command > 0) {
            uint8_t byte = b[off++];
            switch (v->remaining_command) {
            case 5: v->current_command = byte; break;
            case 4: v->remaining_content = (int32_t)byte << 8; break;
            case 3: v->remaining_content |= byte; break;
            case 2: v->remaining_padding = (int32_t)byte << 8; break;
            case 1: v->remaining_padding |= byte; break;
            default: break;
            }
            v->remaining_command--;
        } else if (v->remaining_content > 0) {
            size_t take = (size_t)v->remaining_content;
            if (take > len - off)
                take = len - off;
            memcpy(out + n, b + off, take);
            n += take;
            off += take;
            v->remaining_content -= (int32_t)take;
        } else if (v->remaining_padding > 0) {
            size_t skip = (size_t)v->remaining_padding;
            if (skip > len - off)
                skip = len - off;
            off += skip;
            v->remaining_padding -= (int32_t)skip;
        }

        if (v->remaining_command <= 0 && v->remaining_content <= 0 && v->remaining_padding <= 0) {
            if (v->current_command == LC_VISION_CONTINUE) {
                v->remaining_command = 5; /* another block follows */
            } else {
                /* Back to the starting state whatever the command was, and what is left of this
                 * buffer comes out as it stands — "shouldn't happen", says the reference, and
                 * keeps it rather than dropping it. */
                v->remaining_command = -1;
                v->remaining_content = -1;
                v->remaining_padding = -1;
                memcpy(out + n, b + off, len - off);
                n += len - off;
                break;
            }
        }
    }
    return n;
}

int lc_vision_read(lc_vision *v, const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t out_cap, size_t *out_len, int *direct)
{
    *out_len = 0;
    *direct = v->direct_in;
    if (in_len > out_cap)
        return -1;

    /* Already direct: the reader returns what it read and does nothing else. */
    if (v->direct_in) {
        memcpy(out, in, in_len);
        *out_len = in_len;
        return 0;
    }

    size_t off = 0;
    while (off < in_len) {
        size_t len = in_len - off;
        if (len > READ_SIZE)
            len = READ_SIZE;
        uint8_t *got = out + *out_len;
        size_t   n = len;

        if (v->within_padding || v->packets_to_filter > 0) {
            n = unpad_buffer(v, in + off, len, got);
            /* The verdict after the read, from where the counters stand at its end. A command
             * other than the three leaves it as it was — the reference only logs it. */
            if (v->remaining_content > 0 || v->remaining_padding > 0 ||
                v->current_command == LC_VISION_CONTINUE) {
                v->within_padding = 1;
            } else if (v->current_command == LC_VISION_END) {
                v->within_padding = 0;
            } else if (v->current_command == LC_VISION_DIRECT) {
                v->within_padding = 0;
                v->direct_in = 1;
            }
        } else {
            memcpy(got, in + off, len);
        }
        off += len;

        /* The filter sees what the read yielded, and only a read that yielded something: a
         * buffer that was all padding is dropped from the MultiBuffer before XtlsFilterTls counts
         * it (vendor/Xray-core/proxy/proxy.go:239-241, :255-257). */
        if (n > 0)
            lc_vision_filter(v, got, n);
        *out_len += n;

        if (v->direct_in) {
            /* The rest of the record is the connection's `input`, merged as it stands and never
             * offered to the filter (vendor/Xray-core/proxy/proxy.go:259-266). */
            memcpy(out + *out_len, in + off, in_len - off);
            *out_len += in_len - off;
            break;
        }
    }

    *direct = v->direct_in;
    return 0;
}

void lc_vision_filter(lc_vision *v, const uint8_t *data, size_t len)
{
    if (v->packets_to_filter <= 0)
        return;
    (void)lc_vision_filter_piece(v, data, len);
}

int lc_vision_filter_piece(lc_vision *v, const uint8_t *data, size_t len)
{
    v->packets_to_filter--;

    if (len >= 6u) {
        if (memcmp(data, tls_server_handshake_start, 3) == 0 && data[5] == 0x02u) {
            /* A ServerHello. Its length tells us how far to keep looking for the marker that says
             * TLS 1.3, because the version lives in an extension rather than in the header. */
            v->remaining_server_hello = ((int32_t)data[3] << 8 | data[4]) + 5;
            v->is_tls12_or_above = 1;
            v->is_tls = 1;
            if (len >= 79u && v->remaining_server_hello >= 79) {
                int32_t sid = data[43];
                if ((size_t)(43 + sid + 3) <= len)
                    v->cipher = (uint16_t)((uint16_t)data[43 + sid + 1] << 8 | data[43 + sid + 2]);
            }
        } else if (memcmp(data, tls_client_handshake_start, 2) == 0 && data[5] == 0x01u) {
            v->is_tls = 1;
        }
    }

    if (v->remaining_server_hello > 0) {
        size_t end = (size_t)v->remaining_server_hello;
        if (end > len)
            end = len;
        v->remaining_server_hello -= (int32_t)len;

        /* supported_versions carrying exactly one version is what a TLS 1.3 ServerHello has, and
         * finding it is the moment direct copy becomes possible. */
        int found = 0;
        if (end >= sizeof tls13_supported_versions) {
            for (size_t i = 0; i + sizeof tls13_supported_versions <= end; i++) {
                if (memcmp(data + i, tls13_supported_versions, sizeof tls13_supported_versions) == 0) {
                    found = 1;
                    break;
                }
            }
        }
        if (found) {
            /* Every TLS 1.3 suite except AES-128-CCM-8 permits direct copy — and "TLS 1.3 suite"
             * is a membership test, not an inequality. vendor/Xray-core/proxy/proxy.go:655-659
             * looks the cipher up in Tls13CipherSuiteDic (0x1301..0x1305, vendor/Xray-core/proxy/proxy.go:43-49) and
             * enables XTLS only when the lookup SUCCEEDS and the name is not
             * TLS_AES_128_CCM_8_SHA256:
             *
             *     v, ok := Tls13CipherSuiteDic[trafficState.Cipher]
             *     if !ok { v = "Old cipher: " … } else if v != "TLS_AES_128_CCM_8_SHA256" {
             *         trafficState.EnableXtls = true }
             *
             * `cipher != 0x1305` dropped the `ok` half, so a cipher that was never parsed (0, the
             * common case when the ServerHello is short) and every TLS 1.2 suite enabled direct
             * copy — the quiet failure this file's header warns about. */
            if (v->cipher >= 0x1301u && v->cipher <= 0x1304u)
                v->enable_xtls = 1;
            v->packets_to_filter = 0;
            return 1;
        } else if (v->remaining_server_hello <= 0) {
            v->packets_to_filter = 0; /* TLS 1.2: stay padded for the whole connection */
            return 1;
        }
    }
    return 0;
}
