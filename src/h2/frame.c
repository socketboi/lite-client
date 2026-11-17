#include "h2/frame.h"

#include <string.h>

/* Settings identifiers, of which this client has an opinion about four. */
#define SETTING_HEADER_TABLE_SIZE 0x1u
#define SETTING_MAX_FRAME_SIZE 0x5u
#define SETTING_MAX_HEADER_LIST_SIZE 0x6u
#define SETTING_ENABLE_PUSH 0x2u
#define SETTING_INITIAL_WINDOW_SIZE 0x4u

static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

size_t lc_h2_preface(uint8_t *out, size_t cap)
{
    size_t n = sizeof preface - 1u;
    if (cap < n)
        return 0;
    memcpy(out, preface, n);
    return n;
}

size_t lc_h2_put_header(uint8_t *out, size_t cap, uint32_t len, uint8_t type, uint8_t flags,
                        uint32_t stream)
{
    if (cap < LC_H2_HEADER || len > 0xffffffu)
        return 0;

    out[0] = (uint8_t)(len >> 16);
    out[1] = (uint8_t)(len >> 8);
    out[2] = (uint8_t)len;
    out[3] = type;
    out[4] = flags;
    /* The top bit is reserved and must be sent as zero. Masked rather than assumed: a stream id
     * with it set is a different number to every peer that reads it. */
    out[5] = (uint8_t)(stream >> 24 & 0x7fu);
    out[6] = (uint8_t)(stream >> 16);
    out[7] = (uint8_t)(stream >> 8);
    out[8] = (uint8_t)stream;
    return LC_H2_HEADER;
}

int lc_h2_get_header(const uint8_t *in, size_t len, lc_h2_hd *out)
{
    if (len < LC_H2_HEADER)
        return -1;

    out->len = (uint32_t)in[0] << 16 | (uint32_t)in[1] << 8 | in[2];
    out->type = in[3];
    out->flags = in[4];
    /* Ignored on the way in, as the RFC requires — not treated as part of the number. */
    out->stream = ((uint32_t)in[5] & 0x7fu) << 24 | (uint32_t)in[6] << 16 | (uint32_t)in[7] << 8 |
                  in[8];

    /* A frame larger than what we advertised is a peer that ignored our SETTINGS, and believing its
     * length would mean waiting for bytes that are not coming while the connection stalls. */
    if (out->len > LC_H2_MAX_READ_FRAME)
        return -1;
    return 0;
}

static size_t put_setting(uint8_t *out, uint16_t id, uint32_t value)
{
    out[0] = (uint8_t)(id >> 8);
    out[1] = (uint8_t)id;
    out[2] = (uint8_t)(value >> 24);
    out[3] = (uint8_t)(value >> 16);
    out[4] = (uint8_t)(value >> 8);
    out[5] = (uint8_t)value;
    return 6u;
}

size_t lc_h2_settings(uint8_t *out, size_t cap, uint32_t initial_window)
{
    uint8_t body[24];
    size_t  b = 0;

    /* THE SET AND THE ORDER ARE THE REFERENCE'S, because between them they are the HTTP/2
     * fingerprint — the thing read off a connection the way JA3 is read off a ClientHello. Go's
     * client builds the frame in exactly this order:
     *
     *     initialSettings := []Setting{
     *         {ID: SettingEnablePush, Val: 0},
     *         {ID: SettingInitialWindowSize, Val: uint32(cc.initialStreamRecvWindowSize)},
     *     }
     *     initialSettings = append(initialSettings, Setting{ID: SettingMaxFrameSize, ...})
     *     if max := t.maxHeaderListSize(); max != 0 { ...SettingMaxHeaderListSize... }
     *     if maxHeaderTableSize != initialHeaderTableSize { ...SettingHeaderTableSize... }
     *                                    (vendor/x-net/http2/transport.go:527-537)
     *
     * Two things follow that this frame used to get wrong. The order began with
     * SETTING_HEADER_TABLE_SIZE, which the reference puts LAST when it sends it at all; and it sent
     * that setting with a zero, which the reference never sends, because it emits it only to ask
     * for something other than the four-kilobyte default. Announcing zero is a client saying "I
     * keep no dynamic table", and nothing else on the wire says that. The decoder now keeps one —
     * see src/h2/hpack.h — so the announcement is gone with it. */
    b += put_setting(body + b, SETTING_ENABLE_PUSH, 0);
    b += put_setting(body + b, SETTING_INITIAL_WINDOW_SIZE, initial_window);
    b += put_setting(body + b, SETTING_MAX_FRAME_SIZE, LC_H2_MAX_READ_FRAME);
    b += put_setting(body + b, SETTING_MAX_HEADER_LIST_SIZE, LC_H2_MAX_HEADER_LIST);

    if (cap < LC_H2_HEADER + b)
        return 0;
    if (lc_h2_put_header(out, cap, (uint32_t)b, LC_H2_SETTINGS, 0, 0) == 0)
        return 0;
    memcpy(out + LC_H2_HEADER, body, b);
    return LC_H2_HEADER + b;
}

size_t lc_h2_settings_ack(uint8_t *out, size_t cap)
{
    return lc_h2_put_header(out, cap, 0, LC_H2_SETTINGS, LC_H2_ACK, 0);
}

size_t lc_h2_headers(uint8_t *out, size_t cap, uint32_t stream, const uint8_t *block, size_t len,
                     int end_stream)
{
    /* END_HEADERS always, because this client never continues a header block into a second frame.
     * It does not need to: its blocks are a few hundred bytes and the smallest frame size any peer
     * may advertise is sixteen kilobytes. */
    uint8_t flags = LC_H2_END_HEADERS | (end_stream ? LC_H2_END_STREAM : 0u);

    if (len > LC_H2_MAX_FRAME || cap < LC_H2_HEADER + len)
        return 0;
    if (lc_h2_put_header(out, cap, (uint32_t)len, LC_H2_HEADERS, flags, stream) == 0)
        return 0;
    memcpy(out + LC_H2_HEADER, block, len);
    return LC_H2_HEADER + len;
}

size_t lc_h2_data_header(uint8_t *out, size_t cap, uint32_t stream, size_t len, int end_stream)
{
    if (len > LC_H2_MAX_FRAME)
        return 0;
    return lc_h2_put_header(out, cap, (uint32_t)len, LC_H2_DATA,
                            end_stream ? LC_H2_END_STREAM : 0u, stream);
}

size_t lc_h2_window_update(uint8_t *out, size_t cap, uint32_t stream, uint32_t increment)
{
    /* Zero is not a permitted increment — it is a protocol error rather than a no-op — so a caller
     * with nothing to give back is refused here instead of on the connection. */
    if (increment == 0 || increment > 0x7fffffffu || cap < LC_H2_HEADER + 4u)
        return 0;
    if (lc_h2_put_header(out, cap, 4u, LC_H2_WINDOW_UPDATE, 0, stream) == 0)
        return 0;

    out[LC_H2_HEADER + 0] = (uint8_t)(increment >> 24 & 0x7fu);
    out[LC_H2_HEADER + 1] = (uint8_t)(increment >> 16);
    out[LC_H2_HEADER + 2] = (uint8_t)(increment >> 8);
    out[LC_H2_HEADER + 3] = (uint8_t)increment;
    return LC_H2_HEADER + 4u;
}

int lc_h2_data_body(const lc_h2_hd *hd, const uint8_t *payload, const uint8_t **body,
                    size_t *body_len)
{
    if ((hd->flags & LC_H2_PADDED) == 0u) {
        *body = payload;
        *body_len = hd->len;
        return 0;
    }
    if (hd->len < 1u || payload[0] >= hd->len)
        return -1;
    *body = payload + 1;
    *body_len = hd->len - 1u - payload[0];
    return 0;
}
