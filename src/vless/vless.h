/* VLESS, client side.
 *
 * The whole protocol is a header on the first packet and a header on the first reply. There is no
 * encryption of its own and no negotiation: VLESS deliberately does none of that, because the TLS
 * underneath already does it, and doing it twice is what makes "TLS in TLS" recognisable.
 *
 *   request:  u8 version=0, 16-byte uuid, u8 addons length + addons,
 *             u8 command, u16 port, u8 address type, address
 *   response: u8 version, u8 addons length + addons, then the stream
 *
 * The addons carry the flow name, and getting it wrong is a silent failure of a specific kind: a
 * server whose user is configured with a flow rejects a client that sends none, and the rejection
 * looks like the connection simply not working. */
#ifndef LC_VLESS_H
#define LC_VLESS_H

#include <stddef.h>
#include <stdint.h>

#define LC_VLESS_UUID 16u

/* Commands. UDP rides over the same stream with its own framing; MUX is not implemented. */
#define LC_VLESS_TCP 0x01u
#define LC_VLESS_UDP 0x02u
/* Mux, which is what a client with Vision actually sends for UDP — see vless/xudp.h. */
#define LC_VLESS_MUX 0x03u

/* Address types, as they appear on the wire. */
#define LC_VLESS_ADDR_IPV4 0x01u
#define LC_VLESS_ADDR_DOMAIN 0x02u
#define LC_VLESS_ADDR_IPV6 0x03u

/* THE ONLY FLOW THIS PROTOCOL HAS, IN THE TWO SPELLINGS THE REFERENCE ACCEPTS. Xray names two
 * constants and one of them is the absence of a flow: `None = "none"`, `XRV = "xtls-rprx-vision"`
 * (vendor/Xray-core/proxy/vless/vless.go:17-18). The third string is not a third flow — it is XRV
 * with one permission added, and the reference says so by falling through:
 *
 *     case vless.XRV + "-udp443":
 *         allowUDP443 = true
 *         requestAddons.Flow = requestAddons.Flow[:16]
 *         fallthrough
 *     case vless.XRV:
 *                    (vendor/Xray-core/proxy/vless/outbound/outbound.go:247-252)
 *
 * Everything else is not a flow with a different meaning, it is not a flow. */
#define LC_VLESS_FLOW_VISION "xtls-rprx-vision"
#define LC_VLESS_FLOW_VISION_UDP443 LC_VLESS_FLOW_VISION "-udp443"

/* Which of the two `flow` is: 1 for Vision in either spelling, 0 for none, -1 for a string that is
 * neither.
 *
 * One predicate rather than a strcmp at each site, because there were two sites and they disagreed.
 * The wire format asked "is it empty" and wrote the addons for anything that was not; the framing
 * asked "is it exactly Vision" — so a flow of "xtls-rprx-vision-udp443" produced a request carrying
 * an addons block with that name and no Vision framing behind it. Xray's client cannot produce that
 * pairing. */
int lc_vless_flow(const char *flow);

/* Whether this flow carries the reference's `allowUDP443`.
 *
 * A SEPARATE QUESTION FROM "IS IT VISION", because the reference asks it separately and answers it
 * differently: with plain Vision a UDP request to port 443 is REFUSED before it is sent —
 *
 *     case protocol.RequestCommandUDP:
 *         if !allowUDP443 && request.Port == 443 {
 *             return errors.New("XTLS rejected UDP/443 traffic").AtInfo()
 *         }
 *                    (vendor/Xray-core/proxy/vless/outbound/outbound.go:255-258)
 *
 * — and only the "-udp443" spelling lifts it. Without this the client sends the node datagrams that
 * a real Xray client with the same configuration would never send, which is a difference in
 * behaviour rather than in one packet's bytes. */
int lc_vless_flow_allows_udp443(const char *flow);

/* What the addons block must carry for this flow: the reference truncates the value to sixteen
 * bytes (`requestAddons.Flow[:16]`), so "-udp443" travels as plain Vision and the permission stays
 * on the client side where it was decided. NULL when there is no flow to announce. */
const char *lc_vless_flow_wire(const char *flow);

/* Parses "c40253ba-8b09-424c-a26e-e95808c4c4f9" into sixteen bytes. */
int lc_vless_uuid(const char *text, uint8_t out[LC_VLESS_UUID]);

/* Builds the request header for a TCP target.
 *
 * `flow` is the XTLS flow name or NULL for none. It must match what the server has configured for
 * this user: "xtls-rprx-vision" against a Vision user, NULL against a plain one. A mismatch is
 * refused by the server without an error the client can see. */
int lc_vless_request(const uint8_t uuid[LC_VLESS_UUID], const char *flow,
                     const char *host, uint16_t port,
                     uint8_t *out, size_t out_cap, size_t *out_len);

/* The same, for a datagram target.
 *
 * UDP does not get a connection of its own: it rides the same stream, and every datagram is
 * length-prefixed so the far end can find the boundaries a packet network would otherwise have
 * given it for free. One stream carries one destination, which is why a resolver and a game server
 * are two streams and not one.
 *
 * ⚠️ THE FLOW TRAVELS, AND THIS SAID THE OPPOSITE UNTIL 2026-09-02. What stood here was "No flow:
 * Vision frames a byte stream, and a sequence of datagrams is not one. Xray refuses the combination"
 * — an accurate description of a decision that was made, tried against a live Xray, and REVERSED.
 * The inbound refused it in as many words: `account ... is rejected since the client flow is empty`.
 * The code has passed `flow` through ever since (src/vless/vless.c:238 — ours, and written with its
 * directory so the sieve does not go looking for a `vless.c` in vendor), which is also what the
 * reference does
 * — vendor/Xray-core/proxy/vless/outbound/outbound.go:303-307 leaves requestAddons.Flow untouched
 * when it rewrites the request into Mux.
 *
 * So the sentence survived the change it described and went on contradicting the function under it.
 * The account of WHY the flow rides on a datagram request is inside lc_vless_request_udp, next to
 * the line that sends it. */
int lc_vless_request_udp(const uint8_t uuid[LC_VLESS_UUID], const char *flow,
                         const char *host, uint16_t port,
                         uint8_t *out, size_t out_cap, size_t *out_len);

/* The other UDP request, command 0x02 with the destination in the header, which the reference sends
 * when it does NOT rewrite into Mux: no Vision flow and — with cone, its default — a first datagram
 * for port 53 or 443 (vendor/Xray-core/proxy/vless/outbound/outbound.go:303-307, `cone` from
 * vendor/Xray-core/core/xray.go:195-196). Its body is datagrams as a 16-bit length and the bytes,
 * both ways (EncodeBodyAddons and DecodeBodyAddons, vendor/Xray-core/proxy/vless/encoding/addons.go:
 * 65-74, :76-85). */
int lc_vless_request_udp_plain(const uint8_t uuid[LC_VLESS_UUID], const char *flow,
                               const char *host, uint16_t port,
                               uint8_t *out, size_t out_cap, size_t *out_len);

/* Reads the response header out of one buffer, reporting how many bytes of it were consumed so the
 * caller can find where the stream begins. -1 when the buffer does not hold it whole, when the version
 * is not ours and when the addons do not unmarshal — three answers in one, which is why only lc-fetch,
 * a one-shot diagnostic, still asks this. The tunnel reads the header as the reference does, from the
 * stream across records: lc_vless_response_feed below.
 *
 * ⚠️ "NOT SPLIT INTO TWO RETURNS TODAY … made blind" stood here until 2026-09-27, when the split was
 * made and held to the reference on a live Xray; the addons were not read at all before then. */
int lc_vless_response(const uint8_t *buf, size_t len, size_t *header_len);

/* The response header as the reference reads it: from the stream, across as many records as it
 * takes, the addons unmarshalled — see lc_vless_response_feed. */
typedef struct {
    uint8_t buf[2u + 255u];
    size_t  len;
} lc_vless_resp;

/* Feeds the start of the node's stream. `*took` is how many of `len` bytes belong to the header.
 * Returns 1 once the header is whole and good, 0 while more is needed, -1 when it is refused: a
 * version that is not ours, or addons that do not unmarshal. */
int lc_vless_response_feed(lc_vless_resp *r, const uint8_t *buf, size_t len, size_t *took);

/* Whether `n` bytes of response addons unmarshal as the reference's Addons message: see pb_fields. */
int lc_vless_addons_ok(const uint8_t *p, size_t n);

#endif
