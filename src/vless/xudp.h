/* Xray's xudp framing: how a stock client carries proxied UDP inside a VLESS stream.
 *
 * WHY THIS EXISTS AT ALL. A VLESS client does not send UDP as command 0x02 with a length in front
 * of each datagram — not when Vision is on. It converts the request to Mux:
 *
 *     if request.Command == protocol.RequestCommandUDP &&
 *        (requestAddons.Flow == vless.XRV || (h.cone && request.Port != 53 && request.Port != 443)) {
 *         request.Command = protocol.RequestCommandMux
 *         request.Address = net.DomainAddress("v1.mux.cool")
 *         request.Port    = net.Port(666)
 *     }        (vendor/Xray-core/proxy/vless/outbound/outbound.go:303-307)
 *
 * and then wraps every datagram with xudp.NewPacketWriter (:319-321). Note which half of that
 * condition fires here: with flow xtls-rprx-vision the FIRST disjunct is true, so it applies to
 * every port — 53 and 443 included. The ports named in the second disjunct are a red herring for a
 * client that uses Vision, which is this one.
 *
 * THE FRAME, from vendor/Xray-core/common/xudp/xudp.go:96-135:
 *
 *     u16   meta length          everything after this field up to the payload length
 *     u16   Mux session id       zero here: one stream carries one session
 *     u8    status               1 New on the first datagram, 2 Keep afterwards
 *     u8    option               1, meaning a payload follows
 *     u8    network              2 (UDP) — on New always, later only with an address
 *     port + address             PortThenAddress, the same order the VLESS header uses
 *     [8]   global id            eight bytes, present when the datagram carries a destination
 *     u16   payload length
 *     ...   payload
 *
 * THE GLOBAL ID, which this client sent as zeros for as long as a stream carried one destination.
 * What it is and why it is no longer zero is below; the measurement that settled its shape came
 * from a capture of a real Xray client (2026-08-25 — a TLS server printing the plaintext stream,
 * Xray built from source pointed at it, socks inbound with udp enabled):
 *
 *   0014  0000 01 01 02 0035 01 08080808  8e79a356943a223d  001d …
 *   ^meta 20                              ^ the global ID, and it is NOT zero
 *
 * So the eight bytes ARE written — that part this client already had right, and a first capture
 * through a dokodemo-door with a FIXED destination showed twelve bytes of metadata instead of
 * twenty, because `if b.UDP != nil` is false when the packet does not carry its own destination.
 * That measured the wrong case; a transparent interceptor is the other one.
 *
 * What was wrong is the VALUE and the reasoning for it. GetGlobalID (:65-79) returns zeros only
 * when cone mode is off — and cone is ON by default — or when the inbound is not one of
 * dokodemo-door, socks, shadowsocks, tun. This client is closest in role to tun, which is IN that
 * list, so "not an Xray inbound, therefore zeros" does not follow: a stock client in this position
 * sends a keyed BLAKE3 of its own client's source address.
 *
 * ⚠️ ZEROS WERE RIGHT HERE UNTIL THE SESSION MODEL CHANGED, and the reason is worth keeping because
 * it is what a reader will otherwise rediscover the hard way. A non-zero id is a map key:
 * `XUDPManager.Map[meta.GlobalID]`, and a second stream arriving with an id already in the map is
 * an "XUDP hit" that DETACHES the previous one — `x.Mux.Close(false)`
 * (vendor/Xray-core/common/mux/server.go:195-227). While this client opened a stream per
 * DESTINATION, a shared per-source id would have made every new destination tear down the one
 * before it: a browser opening QUIC to ten hosts would have cut nine of its own sessions. Zeros are
 * explicitly handled for exactly that case — "MUST ignore empty Global ID" (vendor/Xray-core/common/mux/server.go:195) — and
 * ignoring is at least correct.
 *
 * That is no longer the shape. A datagram session now belongs to the CLIENT and carries every
 * address it talks to on one stream, which is upstream's own model and the thing the address in
 * each frame exists for. With one stream per source there is no second stream to detach, so the id
 * can be what it is meant to be: eight bytes naming this client, stable while it keeps talking and
 * different from every other client's.
 *
 * WHAT IT BUYS is the session reuse those eight bytes key: full-cone NAT. Without it a household
 * gets symmetric NAT for anything peer to peer — calls, games, WebRTC.
 *
 * The VALUE does not have to be the reference's, and that is not an assumption — it is what the
 * node's own code does with it. Upstream derives its own from the inbound source with a keyed
 * BLAKE3 (xudp.go:65-79), but GetGlobalID is the CLIENT half; the server only ever uses the eight
 * bytes as a map key:
 *
 *     if meta.GlobalID != [8]byte{} {          // MUST ignore empty Global ID
 *         x := XUDPManager.Map[meta.GlobalID]
 *         if x == nil {
 *             x = &XUDP{GlobalID: meta.GlobalID}
 *             XUDPManager.Map[meta.GlobalID] = x
 *                                          (vendor/Xray-core/common/mux/server.go:195-204)
 *
 * — looked up, created when absent, stored back. Nothing recomputes the hash and nothing compares
 * it against the source address, so any value that is stable per client and distinct between
 * clients does the job. ⚠️ Said with the citation because a reverse audit reads GetGlobalID alone
 * and concludes the opposite — "must match the hash computed from inbound.Source.String() for a
 * successful handshake" — which would mean carrying BLAKE3 to match something nothing checks.
 *
 * See client_global_id in lc-tunnel for what is derived here, why the key is drawn per run, and why
 * it is drawn BEFORE the workers fork. */
#ifndef LC_XUDP_H
#define LC_XUDP_H

#include "vless/vless.h"

#include <stddef.h>
#include <stdint.h>

/* What the Mux request names instead of the real destination. The destination moves into the xudp
 * frame; the VLESS header stops carrying it. */
#define LC_XUDP_MUX_HOST "v1.mux.cool"
#define LC_XUDP_MUX_PORT 666u

#define LC_XUDP_STATUS_NEW 0x01u
#define LC_XUDP_STATUS_KEEP 0x02u
/* End, as the Mux layer numbers it (vendor/Xray-core/common/mux/frame.go:22). Not to be confused
 * with the 4 the xudp READER treats as "discard": that switch is xudp.go:164-181 and belongs to a
 * different layer. */
#define LC_XUDP_STATUS_END 0x03u
#define LC_XUDP_GLOBAL_ID 8u

/* Frames one datagram. `first` marks the first on the stream, which is the one that carries the
 * destination and the status New.
 *
 * `global_id` is eight bytes identifying the CLIENT this stream belongs to, and it rides only on
 * that first frame. What the node does with it is keep one UDP mapping per value — see the header
 * of this file — so it must be stable for one client and different between clients. NULL sends
 * zeros, which the node is required to ignore.
 *
 * Returns 0, or -1 when it would not fit. */
int lc_xudp_wrap(int first, const char *host, uint16_t port, const uint8_t global_id[8],
                 const uint8_t *payload, size_t len,
                 uint8_t *out, size_t out_cap, size_t *out_len);

/* The same frame for a datagram with no address of its own — what the reference's UDP inbound hands
 * over when its listener is not transparent, `b.UDP` left nil (vendor/Xray-core/app/proxyman/inbound/
 * worker.go:314-323): the New frame without the global id, and Keep frames with neither the network
 * nor an address, a meta block of four bytes. */
int lc_xudp_wrap_unaddressed(int first, const char *host, uint16_t port, const uint8_t *payload,
                             size_t len, uint8_t *out, size_t out_cap, size_t *out_len);

/* NO END FRAME IS BUILT HERE, and one was — "the frame that ends the session, which the reference
 * sends and this client did not". It is sent by Mux's Writer.Close, on the Mux client's path; a VLESS
 * outbound with the Vision flow writes datagrams through xudp's PacketWriter, which has no Close
 * (vendor/Xray-core/common/xudp/xudp.go:81-136), and simply closes the connection. The status is
 * still READ — lc_xudp_next reports it as LC_XUDP_ENDED — because a server may send it. */

/* The node says this stream is over — the reference's `io.EOF`, which is an ENDING and not a fault.
 *
 * It had no value here, and that was the divergence rather than a missing name: the reference
 * answers two inputs with `io.EOF` — a meta block under four bytes (`if l < 4 { return nil, io.EOF }`,
 * vendor/Xray-core/common/xudp/xudp.go:156-158) and any status that is not Keep or KeepAlive, which
 * is where End (0x03) lands (`default: ... return io.EOF`, :164-181) — and this contract could only
 * say "impossible". So a session the node closed in the ordinary way was reported as broken
 * framing, and lc-tunnel tore it down through the failure path instead of the one a peer's
 * end-of-stream already takes. */
#define LC_XUDP_ENDED 2

/* Takes the first whole frame out of `buf`: 1 and the payload, 0 when the buffer does not hold a
 * whole one yet, LC_XUDP_ENDED when the node ended the stream, -1 when the framing is impossible.
 *
 * Stated here rather than by reference, which is how it used to be written — "the same contract
 * lc_vless_udp_next has". That function is gone (nothing called it), and it had never implemented
 * the third case anyway: it could return only 1 or 0, so the sentence borrowed a refusal from a
 * function that did not refuse. A contract described by pointing at another one is a contract that
 * outlives what it points at. */
/* `host` receives the address the frame states, empty when it states none — an End frame, or a Keep
 * that carries no payload. It is the address the datagram came FROM, and a stream carrying more than
 * one destination cannot route a reply without it: the xudp session belongs to the client, not to a
 * destination, and every frame says where its datagram belongs. `host_cap` must be at least
 * INET6_ADDRSTRLEN for a literal, or one more than the longest name expected. */
int lc_xudp_next(const uint8_t *buf, size_t len,
                 char *host, size_t host_cap, uint16_t *port,
                 const uint8_t **payload, size_t *payload_len, size_t *used);

#endif
