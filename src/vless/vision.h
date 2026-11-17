/* XTLS Vision — the reason this client can be fast on a router that cannot do crypto.
 *
 * A VLESS connection normally carries the client's TLS inside our TLS: everything is encrypted
 * twice, and on the measured hardware that costs 25-37 Mbit/s. Vision removes the second layer once
 * it has seen enough to be sure the inner stream is itself TLS 1.3 — from then on the payload is
 * passed through untouched and can be spliced by the kernel. The same box relays at 519 Mbit/s that
 * way. It is a factor of fifteen, not a tuning knob.
 *
 * Three mechanisms, and all three have to be exactly right or the server drops the connection with
 * no diagnostic:
 *
 *   padding   every frame carries a header — optionally the user's UUID once — a command, the
 *             content length and a padding length. The lengths are what let the receiver find the
 *             frame boundary; the padding itself hides how long the real data was.
 *   filtering the first few packets are inspected to decide whether the inner stream is TLS 1.3.
 *             Only then is direct copy allowed.
 *   commands  continue, end, direct — and the difference between the last two is the whole of this
 *             file's history. "End" means the framing stops: the payload is no longer wrapped, but
 *             it still arrives inside the TLS record layer. "Direct" means the record layer stops
 *             too: everything after that frame is the inner connection's own bytes, straight off
 *             the socket. Conflating them reads TLS records as payload and hands the client a
 *             stream that is wrong from the first byte — and wrong quietly, because a download of a
 *             known length still finishes and still reports success. What it costs is only visible
 *             where something checks: the inner TLS fails its MAC, and a browser shows a page that
 *             does not load for no stated reason.
 */
#ifndef LC_VISION_H
#define LC_VISION_H

#include "vless/vless.h"

#include <stddef.h>
#include <stdint.h>

/* ⚠️ FIVE NUMBERS THAT MUST BE THE REFERENCE'S, AND NOT ONE OF THEM CITED A LINE UNTIL NOW.
 *
 * A header is where the sieve is blindest: it holds no code, so nothing here is ever the subject of
 * a finding, and yet every constant below is a wire format. Get one wrong and the server drops the
 * connection with no diagnostic — which is this file's own opening sentence, said about the code
 * and never about the numbers. They are pinned now, each at its definition.
 *
 * Frame commands, as they appear in the padding header:
 *
 *     CommandPaddingContinue byte = 0x00
 *     CommandPaddingEnd      byte = 0x01
 *     CommandPaddingDirect   byte = 0x02
 *                                  (vendor/Xray-core/proxy/proxy.go:56-58) */
#define LC_VISION_CONTINUE 0x00u
#define LC_VISION_END 0x01u
#define LC_VISION_DIRECT 0x02u

/* The padding header: command, content length, padding length. The UUID, when present, precedes it
 * and appears exactly once per direction — which is the reference's single write, five bytes and no
 * more: `newbuffer.Write([]byte{command, byte(contentLen >> 8), byte(contentLen),
 * byte(paddingLen >> 8), byte(paddingLen)})` (vendor/Xray-core/proxy/proxy.go:528). */
#define LC_VISION_HEADER 5u

/* How many packets are inspected before giving up on recognising TLS. Xray uses eight, and it is a
 * field with a default rather than a constant: `NumberOfPacketToFilter: 8`
 * (vendor/Xray-core/proxy/proxy.go:145). */
#define LC_VISION_FILTER_PACKETS 8

/* WHAT ONE PADDED FRAME CAN GROW TO, so that a caller can reserve room for it.
 *
 * The most content-plus-padding lc_vision_pad will ever emit, and the most a LONG-padded frame
 * reaches — long padding aims at a target between 900 and 1399 whatever the content was, which is
 * the whole reason a small tail can leave larger than it arrived.
 *
 * Both are the reference's arithmetic rather than ours. The long target comes from its own seed,
 * `testseed = []uint32{900, 500, 900, 256}` (vendor/Xray-core/proxy/proxy.go:312): under 900 bytes
 * of content the padding is drawn below 500 and added to 900 minus the content, so the frame lands
 * between 900 and 1399. The ceiling comes from the clamp `if paddingLen > buf.Size-21-contentLen`
 * (vendor/Xray-core/proxy/proxy.go:520) with `Size = 8192`
 * (vendor/Xray-core/common/buf/buffer.go:13) — 8192 less the sixteen-byte UUID and the five-byte
 * header is 8171.
 *
 * Published because the tunnel has to know, before it reads from the client, how much queue room
 * that read could need: one read becomes at most two of these frames, and it used to reserve a
 * round number that was too small for the pair. The numbers stay here rather than in the caller,
 * and vision.c asserts them against the private constants they are derived from, so they cannot
 * drift apart from the padding they describe. */
#define LC_VISION_MAX_BODY 8171u
#define LC_VISION_MAX_LONG 1399u

typedef struct {
    uint8_t uuid[LC_VLESS_UUID];

    /* Outgoing state. Two flags rather than one, for the reason at the top of this file: framing
     * and the record layer end at different moments, and on a stream that is not TLS inside they
     * end at only one of them. */
    int uuid_sent;   /* the UUID rides on the first padded frame only */
    int padding_out; /* still wrapping what we send in Vision frames */
    int direct_out;  /* and no longer sealing it into records either */

    /* What the filter has decided about the inner stream. */
    int      packets_to_filter;
    int      is_tls;
    int      is_tls12_or_above;
    int      enable_xtls; /* the inner stream is TLS 1.3 with a suite that permits direct copy */
    int32_t  remaining_server_hello;
    uint16_t cipher;

    /* Incoming state — the reference's own fields, `OutboundState`, with its starting values
     * (vendor/Xray-core/proxy/proxy.go:161-167): all three counters -1, command 0, and
     * `WithinPaddingBuffers: true`. A frame spans reads: one can arrive in three, and treating a
     * read as a frame is the classic way to get this wrong. */
    int32_t remaining_command;
    int32_t remaining_content;
    int32_t remaining_padding;
    int     current_command;
    int     within_padding; /* WithinPaddingBuffers: every read is still offered to the unpadder */
    int     direct_in;      /* DownlinkReaderDirectCopy: the socket carries the peer's bytes raw */
} lc_vision;

void lc_vision_init(lc_vision *v, const uint8_t uuid[LC_VLESS_UUID]);

/* Wraps one payload into a Vision frame. `command` says what follows; pass LC_VISION_CONTINUE while
 * padding, LC_VISION_DIRECT to announce that the rest is raw.
 *
 * long_padding produces the large random padding used while the inner handshake is in flight — it
 * is what hides the VLESS header and the shape of the TLS records behind it. */
int lc_vision_pad(lc_vision *v, uint8_t command, int long_padding,
                  const uint8_t *payload, size_t payload_len,
                  uint8_t *out, size_t out_cap, size_t *out_len);

/* ONE RECORD'S APPLICATION DATA, READ AS VisionReader READS IT
 * (vendor/Xray-core/proxy/proxy.go:203-257): what ReadMultiBuffer returns, read after read, for the
 * plaintext of one record with the VLESS response header already taken off the first. Pass exactly
 * one record at a time — the reads are cut by the record, which is where the reference's reads end.
 *
 * Each read is unpadded (XtlsUnpadding) while the peer is still framing or the filter still counts,
 * and what it yields goes through the filter — the receive side of lc_vision_filter lives here, as
 * it lives in ReadMultiBuffer. Nothing the peer sends is refused: a buffer that does not open with
 * the UUID passes as it stands, and an unknown command ends its block like "end" does.
 *
 * Returns 0, or -1 when `out_cap` is smaller than `in_len` (what comes out is never longer than
 * what went in). When the peer has announced direct copy, *direct is set and the rest of the record
 * comes out as it stands, as the reference merges the connection's `input` after that read. */
int lc_vision_read(lc_vision *v, const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t out_cap, size_t *out_len, int *direct);

/* Inspects one outgoing or incoming packet to decide whether the inner stream is TLS 1.3. Called
 * for the first few packets only; sets is_tls and enable_xtls as it learns. */
void lc_vision_filter(lc_vision *v, const uint8_t *data, size_t len);

/* THE SAME INSPECTION WITHOUT THE GATE, for a write that carries more than one buffer.
 *
 * XtlsFilterTls asks `NumberOfPacketToFilter > 0` ONCE, before it is called, and then walks every
 * buffer of the MultiBuffer decrementing as it goes — past zero if the write is longer than what was
 * left — and stops early only when it concludes (vendor/Xray-core/proxy/proxy.go:355-357, :624-674).
 * lc_vision_filter is that for a write of one buffer. A write of several calls this once per buffer,
 * after asking the gate itself, and stops when this returns 1: the filter reached a verdict and the
 * reference `return`s. */
int lc_vision_filter_piece(lc_vision *v, const uint8_t *data, size_t len);

#endif
