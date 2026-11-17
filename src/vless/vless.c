#include "vless/vless.h"

#include "vless/xudp.h"

#include <arpa/inet.h>

#include <string.h>

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int lc_vless_uuid(const char *text, uint8_t out[LC_VLESS_UUID])
{
    size_t written = 0;
    for (const char *p = text; *p != '\0'; ) {
        if (*p == '-') {
            p++;
            continue;
        }
        int hi = hex_nibble(p[0]);
        int lo = p[1] != '\0' ? hex_nibble(p[1]) : -1;
        if (hi < 0 || lo < 0)
            return -1;
        if (written == LC_VLESS_UUID)
            return -1;
        out[written++] = (uint8_t)(hi << 4 | lo);
        p += 2;
    }
    return written == LC_VLESS_UUID ? 0 : -1;
}

/* The reference's switch, both arms of it. `-udp443` is Vision with one permission added, so it
 * answers 1 here exactly as the plain spelling does; what separates them is
 * lc_vless_flow_allows_udp443, which is the reference's `allowUDP443` and nothing else. */
int lc_vless_flow(const char *flow)
{
    if (flow == NULL || flow[0] == '\0')
        return 0;
    if (strcmp(flow, LC_VLESS_FLOW_VISION) == 0)
        return 1;
    if (strcmp(flow, LC_VLESS_FLOW_VISION_UDP443) == 0)
        return 1;
    return -1;
}

int lc_vless_flow_allows_udp443(const char *flow)
{
    return flow != NULL && strcmp(flow, LC_VLESS_FLOW_VISION_UDP443) == 0;
}

/* `requestAddons.Flow[:16]` — the permission was decided on this side and does not travel. Both
 * spellings therefore leave as the same sixteen bytes, which is what a node sees from Xray. */
const char *lc_vless_flow_wire(const char *flow)
{
    return lc_vless_flow(flow) == 1 ? LC_VLESS_FLOW_VISION : NULL;
}

/* The addons are a protobuf message with one field: Flow, string, field number 1. Written by hand
 * rather than through a protobuf library — one field of one wire type is not worth a dependency, and
 * the encoding is three bytes of preamble around the name.
 *
 * WRITTEN FOR VISION AND FOR NOTHING ELSE, which is the reference's switch rather than a length
 * test: EncodeHeaderAddons marshals the message under `case vless.XRV` and writes a bare zero under
 * `default` (vendor/Xray-core/proxy/vless/encoding/addons.go:17-34). What stood here wrote the
 * message for any non-empty string, so a flow this protocol does not have went out named in a block
 * Xray's own client would not have sent — and the framing decision beside it, which did compare
 * against Vision exactly, stayed off. Two readings of one string, disagreeing.
 *
 * The unknown case cannot arrive any more: every entry point refuses it while it is still an
 * argument, where the operator can be told. This switch is not a second guard for that — it is
 * where the rule belongs, so that the bytes on the wire are right for a caller this file has never
 * heard of. */
static int addons(const char *flow, uint8_t *out, size_t out_cap, size_t *out_len)
{
    /* THE VALUE THAT TRAVELS IS THE TRUNCATED ONE, not the one the operator typed. The reference
     * rewrites the field before the header is encoded — `requestAddons.Flow = requestAddons.Flow[:16]`
     * (vendor/Xray-core/proxy/vless/outbound/outbound.go:250) — so a node never sees "-udp443" on
     * the wire from Xray, and must not see it from us either: the permission it names is spent on
     * the client side, deciding whether a UDP/443 request is made at all. */
    const char *wire = lc_vless_flow_wire(flow);
    if (wire == NULL) {
        *out_len = 0;
        return 0;
    }
    size_t n = strlen(wire);
    if (n > 0x7fu || 2u + n > out_cap)
        return -1;

    out[0] = 0x0au;      /* field 1, length-delimited */
    out[1] = (uint8_t)n; /* varint length; flow names are far below 128 bytes */
    memcpy(out + 2, wire, n);
    *out_len = 2u + n;
    return 0;
}

static int request(const uint8_t uuid[LC_VLESS_UUID], const char *flow, uint8_t command,
                   const char *host, uint16_t port,
                   uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t host_len = strlen(host);
    if (host_len == 0 || host_len > 255u)
        return -1;

    uint8_t add[130];
    size_t  add_len = 0;
    if (addons(flow, add, sizeof add, &add_len) != 0)
        return -1;

    size_t need = 1u + LC_VLESS_UUID + 1u + add_len + 1u + 2u + 1u + 1u + host_len;
    if (need > out_cap)
        return -1;

    size_t i = 0;
    out[i++] = 0x00; /* version */
    memcpy(out + i, uuid, LC_VLESS_UUID);
    i += LC_VLESS_UUID;

    out[i++] = (uint8_t)add_len;
    if (add_len > 0) {
        memcpy(out + i, add, add_len);
        i += add_len;
    }

    out[i++] = command;

    /* A MUX REQUEST CARRIES NO ADDRESS AND NO PORT. The encoder skips them by command:
     *
     *     if request.Command != protocol.RequestCommandMux && request.Command != protocol.RequestCommandRvs {
     *         if err := addrParser.WriteAddressPort(&buffer, request.Address, request.Port); err != nil {
     *                     (vendor/Xray-core/proxy/vless/encoding/encoding.go:50-54)
     *
     * and the decoder puts the name back from the command alone — `case protocol.RequestCommandMux:
     * request.Address = net.DomainAddress("v1.mux.cool")` (:115-116), never reading a port, which is
     * why a real inbound reports the destination as v1.mux.cool:0.
     *
     * Writing them anyway leaves two bytes in the stream that the Mux reader takes for its first
     * frame: a live Xray answered `common/mux: invalid metalen 666`, 666 being the port itself. */
    if (command == LC_VLESS_MUX) {
        *out_len = i;
        return 0;
    }
    out[i++] = (uint8_t)(port >> 8);
    out[i++] = (uint8_t)port;

    /* AN ADDRESS TRAVELS AS AN ADDRESS, AND A NAME AS A NAME.
     *
     * This wrote type 0x02 unconditionally, with the reasoning that sending an address would move
     * name resolution to this side. That reasoning describes a case this client never has: on the
     * intercepted path there IS no name. lc_tproxy_accept and lc_udp_recv fill lc_addr.host with
     * inet_ntop text (src/net/tproxy.c, lines 78, 85, 251 and 265-267) and lc-tunnel copies that
     * into target_host, so what went out as a "domain name" was an IP address spelled in ASCII.
     *
     * Upstream takes the address from the routing target and writes it by family:
     *
     *     tb := p.addrByteMap[address.Family()]
     *     switch address.Family() {
     *     case net.AddressFamilyIPv4, net.AddressFamilyIPv6:
     *         writer.Write([]byte{tb}); writer.Write(address.IP())
     *                        (vendor/Xray-core/common/protocol/address.go:228-240)
     *
     * with the type bytes 1 and 3 (vendor/Xray-core/common/protocol/payload.go:13-15), so a tproxy
     * destination leaves a stock client as 0x01 plus four raw bytes.
     *
     * What it cost: for 142.250.185.78:443 our header was eleven bytes longer than Xray's and its
     * length varied with how many characters the address happened to spell — seven to fifteen —
     * while a real client's is a fixed offset. The header sits outside the padded Vision frame in
     * the same record, so the record length carried both the shift and the smear.
     *
     * And it was not merely longer. A stock server re-parses a domain as an address only when the
     * first character invites it (vendor/Xray-core/common/protocol/address.go:212-218 tests for
     * '[' or a digit), so an IPv6
     * destination such as fd00::1 fell through to isValidDomain and was refused outright.
     *
     * A name is still sent as a name: nothing here resolves anything, so the original concern
     * stands wherever a name is what the caller actually has. */
    unsigned char ip4[4], ip6[16];
    if (host_len > 0 && host_len < 46u && inet_pton(AF_INET, host, ip4) == 1) {
        out[i++] = LC_VLESS_ADDR_IPV4;
        memcpy(out + i, ip4, sizeof ip4);
        i += sizeof ip4;
    } else if (host_len > 0 && host_len < 46u && inet_pton(AF_INET6, host, ip6) == 1) {
        out[i++] = LC_VLESS_ADDR_IPV6;
        memcpy(out + i, ip6, sizeof ip6);
        i += sizeof ip6;
    } else {
        out[i++] = LC_VLESS_ADDR_DOMAIN;
        out[i++] = (uint8_t)host_len;
        memcpy(out + i, host, host_len);
        i += host_len;
    }

    *out_len = i;
    return 0;
}

int lc_vless_request(const uint8_t uuid[LC_VLESS_UUID], const char *flow,
                     const char *host, uint16_t port,
                     uint8_t *out, size_t out_cap, size_t *out_len)
{
    return request(uuid, flow, LC_VLESS_TCP, host, port, out, out_cap, out_len);
}

int lc_vless_request_udp(const uint8_t uuid[LC_VLESS_UUID], const char *flow,
                         const char *host, uint16_t port,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    /* THE DESTINATION DOES NOT TRAVEL IN THIS HEADER, and the command is not 0x02.
     *
     * A client with Vision rewrites a UDP request into a Mux one before it is encoded:
     *
     *     request.Command = protocol.RequestCommandMux
     *     request.Address = net.DomainAddress("v1.mux.cool")
     *     request.Port    = net.Port(666)
     *                (vendor/Xray-core/proxy/vless/outbound/outbound.go:303-307)
     *
     * so the header names a fixed pseudo-destination and the real one moves into the xudp frame
     * around every datagram (vless/xudp.h). host and port are still taken because the caller has
     * them and every other request form uses them; here they are deliberately not written.
     *
     * AND THE FLOW STAYS, which is the opposite of what stood here. The old comment said datagrams
     * carry no flow because Vision frames a byte stream and datagrams are not one — true of command
     * 0x02 and false of this. The rewrite above touches Command, Address and Port and NOTHING else:
     * requestAddons is untouched, so `requestAddons.Flow` is still xtls-rprx-vision when
     * EncodeRequestHeader runs. A real Xray inbound refuses the other way round, and says so:
     * `account ... is rejected since the client flow is empty. Note that the pure TLS proxy has
     * certain TLS in TLS characters.` — which is what a local Xray 26.7.28 answered this client
     * while the flow was being dropped here. */
    (void)host;
    (void)port;
    return request(uuid, flow, LC_VLESS_MUX, LC_XUDP_MUX_HOST, (uint16_t)LC_XUDP_MUX_PORT, out,
                   out_cap, out_len);
}


int lc_vless_response(const uint8_t *buf, size_t len, size_t *header_len)
{
    if (len < 2u)
        return -1;
    /* The version echoes ours; anything else means we are not talking to a VLESS server. */
    if (buf[0] != 0x00)
        return -1;

    size_t add_len = buf[1];
    if (len < 2u + add_len)
        return -1;
    if (!lc_vless_addons_ok(buf + 2, add_len))
        return -1;

    *header_len = 2u + add_len;
    return 0;
}

int lc_vless_request_udp_plain(const uint8_t uuid[LC_VLESS_UUID], const char *flow,
                               const char *host, uint16_t port,
                               uint8_t *out, size_t out_cap, size_t *out_len)
{
    return request(uuid, flow, LC_VLESS_UDP, host, port, out, out_cap, out_len);
}

/* A protobuf varint as protowire.ConsumeVarint takes it: at most ten bytes, the tenth no more than
 * 1. Returns its length, 0 when it is cut short or overflows. */
static size_t pb_varint(const uint8_t *p, size_t n, uint64_t *v)
{
    uint64_t x = 0;
    for (size_t i = 0; i < n && i < 10u; i++) {
        if (i == 9u && p[i] > 1u)
            return 0;
        x |= (uint64_t)(p[i] & 0x7fu) << (7u * i);
        if ((p[i] & 0x80u) == 0) {
            *v = x;
            return i + 1u;
        }
    }
    return 0;
}

/* utf8.Valid: no overlong form, no surrogate, nothing past U+10FFFF. */
static int utf8_valid(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n;) {
        uint8_t  c = p[i];
        size_t   k;
        uint32_t cp, min;
        if (c < 0x80u) {
            i++;
            continue;
        } else if ((c & 0xe0u) == 0xc0u) {
            k = 2u; cp = c & 0x1fu; min = 0x80u;
        } else if ((c & 0xf0u) == 0xe0u) {
            k = 3u; cp = c & 0x0fu; min = 0x800u;
        } else if ((c & 0xf8u) == 0xf0u) {
            k = 4u; cp = c & 0x07u; min = 0x10000u;
        } else {
            return 0;
        }
        if (n - i < k)
            return 0;
        for (size_t j = 1; j < k; j++) {
            if ((p[i + j] & 0xc0u) != 0x80u)
                return 0;
            cp = cp << 6 | (p[i + j] & 0x3fu);
        }
        if (cp < min || cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu))
            return 0;
        i += k;
    }
    return 1;
}

/* One message's fields as proto.Unmarshal walks them into Addons — Flow a string at 1, Seed bytes
 * at 2 (vendor/Xray-core/proxy/vless/encoding/addons.pb.go:26-27): a field number of 0, a wire type
 * of 6 or 7, anything cut short or an end-group with no start is an error, and so is a Flow that is
 * not UTF-8, proto3 strings being checked; a field it does not know, or a known one under another
 * wire type, is kept as unknown and is no error. `group` is the field number of the group being
 * read, 0 at the top. Returns the bytes taken, or 0 for an error. */
static size_t pb_fields(const uint8_t *p, size_t n, uint64_t group, unsigned depth)
{
    size_t off = 0;
    while (off < n) {
        uint64_t tag = 0;
        size_t   t = pb_varint(p + off, n - off, &tag);
        if (t == 0)
            return 0;
        off += t;
        uint64_t num = tag >> 3;
        unsigned wt = (unsigned)(tag & 7u);
        if (num == 0u || num > 0x1fffffffu)
            return 0;
        uint64_t v = 0;
        size_t   k = 0;
        switch (wt) {
        case 0:
            k = pb_varint(p + off, n - off, &v);
            if (k == 0)
                return 0;
            off += k;
            break;
        case 1:
            if (n - off < 8u)
                return 0;
            off += 8u;
            break;
        case 5:
            if (n - off < 4u)
                return 0;
            off += 4u;
            break;
        case 2:
            k = pb_varint(p + off, n - off, &v);
            if (k == 0 || v > n - off - k)
                return 0;
            off += k;
            if (group == 0u && num == 1u && !utf8_valid(p + off, (size_t)v))
                return 0;
            off += (size_t)v;
            break;
        case 3: {
            if (depth >= 256u)
                return 0;
            size_t g = pb_fields(p + off, n - off, num, depth + 1u);
            if (g == 0)
                return 0;
            off += g;
            break;
        }
        case 4:
            /* The end of the group being read, and only that one. */
            return group != 0u && num == group ? off : 0;
        default:
            return 0;
        }
    }
    return group == 0u ? (off == 0 ? 1u : off) : 0;
}

int lc_vless_addons_ok(const uint8_t *p, size_t n)
{
    return n == 0u || pb_fields(p, n, 0u, 0u) != 0;
}

int lc_vless_response_feed(lc_vless_resp *r, const uint8_t *buf, size_t len, size_t *took)
{
    /* DecodeResponseHeader: one byte of version, one of length, that many of addons, each read in
     * full from the stream whatever records it takes (vendor/Xray-core/proxy/vless/encoding/
     * encoding.go:153-172, addons.go:40-58). The version must be ours; the addons must unmarshal. */
    size_t i = 0;
    while (i < len) {
        if (r->len == 0u && buf[i] != 0x00u)
            return -1;
        if (r->len >= 2u && r->len == 2u + (size_t)r->buf[1])
            break;
        r->buf[r->len++] = buf[i++];
        if (r->len >= 2u && r->len == 2u + (size_t)r->buf[1])
            break;
    }
    *took = i;
    if (r->len < 2u || r->len < 2u + (size_t)r->buf[1])
        return 0;
    return lc_vless_addons_ok(r->buf + 2, r->buf[1]) ? 1 : -1;
}
