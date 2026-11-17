#include "vless/xudp.h"

#include <arpa/inet.h>
#include <string.h>

/* Port then address, which is the order xudp's parser is built with:
 *
 *     var AddrParser = protocol.NewAddressParser(
 *         protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
 *         protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
 *         protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
 *         protocol.PortThenAddress(),
 *     )        (vendor/Xray-core/common/xudp/xudp.go:22-27)
 *
 * The type bytes are the same three the VLESS header uses, so an address is spelled identically in
 * both places — and, as there, a literal travels as an address and only a name as a name. */
static int write_addr(const char *host, uint16_t port, uint8_t *out, size_t cap, size_t *used)
{
    size_t host_len = strlen(host);
    if (host_len == 0u || host_len > 255u)
        return -1;

    unsigned char ip4[4], ip6[16];
    size_t         need;
    if (host_len < 46u && inet_pton(AF_INET, host, ip4) == 1)
        need = 2u + 1u + sizeof ip4;
    else if (host_len < 46u && inet_pton(AF_INET6, host, ip6) == 1)
        need = 2u + 1u + sizeof ip6;
    else
        need = 2u + 1u + 1u + host_len;
    if (need > cap)
        return -1;

    size_t i = 0;
    out[i++] = (uint8_t)(port >> 8);
    out[i++] = (uint8_t)port;
    if (host_len < 46u && inet_pton(AF_INET, host, ip4) == 1) {
        out[i++] = LC_VLESS_ADDR_IPV4;
        memcpy(out + i, ip4, sizeof ip4);
        i += sizeof ip4;
    } else if (host_len < 46u && inet_pton(AF_INET6, host, ip6) == 1) {
        out[i++] = LC_VLESS_ADDR_IPV6;
        memcpy(out + i, ip6, sizeof ip6);
        i += sizeof ip6;
    } else {
        out[i++] = LC_VLESS_ADDR_DOMAIN;
        out[i++] = (uint8_t)host_len;
        memcpy(out + i, host, host_len);
        i += host_len;
    }
    *used = i;
    return 0;
}

/* The same three spellings, read back. Mirrors write_addr above, in the same order — port, type,
 * address — because that is what PortThenAddress() means.
 *
 * Bounded by `end` rather than by the buffer: the address lives inside the meta block, and a length
 * inside it that reaches past the block is a frame that lies about itself, not a short read. */
/* net.ParseIP's IPv4 form: four decimal fields, 0..255, no leading zero. */
static int go_ipv4(const char *s, size_t n, uint8_t out[4])
{
    size_t i = 0;
    for (unsigned f = 0; f < 4u; f++) {
        size_t   start = i;
        unsigned v = 0;
        while (i < n && s[i] >= '0' && s[i] <= '9' && i - start < 3u)
            v = v * 10u + (unsigned)(s[i++] - '0');
        if (i == start || v > 255u || (s[start] == '0' && i - start > 1u))
            return 0;
        out[f] = (uint8_t)v;
        if (f < 3u) {
            if (i >= n || s[i] != '.')
                return 0;
            i++;
        }
    }
    return i == n;
}

static int alnum(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/* A domain that is an IP after all, as net.ParseAddress reads it — brackets off, spaces trimmed when
 * an end is not alphanumeric, then net.ParseIP, an IPv4-mapped one being IPv4
 * (vendor/Xray-core/common/net/address.go:79-96, :101-117) — written into `host` as an address.
 * Returns 1 when it was one. */
static int domain_ip(const char *d, size_t n, char *host, size_t host_cap)
{
    if (n >= 2u && d[0] == '[' && d[n - 1u] == ']') {
        d++;
        n -= 2u;
    }
    if (n > 0u && (!alnum(d[0]) || !alnum(d[n - 1u]))) {
        while (n > 0u && (d[0] == ' ' || (d[0] >= '\t' && d[0] <= '\r'))) {
            d++;
            n--;
        }
        while (n > 0u && (d[n - 1u] == ' ' || (d[n - 1u] >= '\t' && d[n - 1u] <= '\r')))
            n--;
    }
    uint8_t a[16];
    if (go_ipv4(d, n, a))
        return inet_ntop(AF_INET, a, host, (socklen_t)host_cap) != NULL;
    char lit[64];
    if (n >= sizeof lit)
        return 0;
    memcpy(lit, d, n);
    lit[n] = '\0';
    if (inet_pton(AF_INET6, lit, a) != 1)
        return 0;
    static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    if (memcmp(a, mapped, sizeof mapped) == 0)
        return inet_ntop(AF_INET, a + 12, host, (socklen_t)host_cap) != NULL;
    return inet_ntop(AF_INET6, a, host, (socklen_t)host_cap) != NULL;
}

static int read_addr(const uint8_t *in, const uint8_t *end, char *host, size_t host_cap,
                     uint16_t *port, size_t *used)
{
    if ((size_t)(end - in) < 3u)
        return -1;
    *port = (uint16_t)((uint16_t)in[0] << 8 | in[1]);
    uint8_t type = in[2];
    size_t  i = 3u;

    if (type == LC_VLESS_ADDR_IPV4) {
        if ((size_t)(end - in) < i + 4u || host_cap < INET_ADDRSTRLEN)
            return -1;
        if (inet_ntop(AF_INET, in + i, host, (socklen_t)host_cap) == NULL)
            return -1;
        i += 4u;
    } else if (type == LC_VLESS_ADDR_IPV6) {
        if ((size_t)(end - in) < i + 16u || host_cap < INET6_ADDRSTRLEN)
            return -1;
        if (inet_ntop(AF_INET6, in + i, host, (socklen_t)host_cap) == NULL)
            return -1;
        i += 16u;
    } else if (type == LC_VLESS_ADDR_DOMAIN) {
        if ((size_t)(end - in) < i + 1u)
            return -1;
        size_t n = in[i++];
        if (n == 0u || (size_t)(end - in) < i + n || host_cap < n + 1u)
            return -1;
        /* ReadAddressPort's domain: one that begins like an IP and parses as one IS one, and anything
         * else must be letters, digits, '-', '.' and '_' or the read fails
         * (vendor/Xray-core/common/protocol/address.go:204-221, isValidDomain at :159-166).
         * ⚠️ UNTIL 2026-09-27 any bytes were taken as a name. */
        const char *d = (const char *)(in + i);
        if (!((d[0] == '[' || (d[0] >= '0' && d[0] <= '9')) && domain_ip(d, n, host, host_cap))) {
            for (size_t k = 0; k < n; k++)
                if (!(alnum(d[k]) || d[k] == '-' || d[k] == '.' || d[k] == '_'))
                    return -1;
            memcpy(host, d, n);
            host[n] = '\0';
        }
        i += n;
    } else {
        return -1;
    }
    *used = i;
    return 0;
}

static int wrap(int first, int addressed, const char *host, uint16_t port,
                const uint8_t global_id[8], const uint8_t *payload, size_t len, uint8_t *out,
                size_t out_cap, size_t *out_len)
{
    /* The reference drops a datagram it cannot frame rather than failing the stream:
     * `if length == 0 || length+666 > buf.Size { continue }` (xudp.go:99-102). The 666 is slack for
     * the meta block and the 8192 is buf.Size. Refused here instead, because this returns one frame
     * to a caller that decides what a refusal means — and the caller already drops.
     *
     * ⚠️ "AND THE CALLER ALREADY DROPS" WAS NOT TRUE WHEN IT WAS WRITTEN, and the sentence is kept
     * above because it is true now and because what it cost is worth reading. The tunnel's UDP path
     * treated a non-zero return from push_up_datagram as fatal and answered it with session_close,
     * so one empty datagram from any LAN device tore down every destination that client's xudp
     * session carried; the pending queue did the same on flush. The drop now happens in the tunnel's
     * own send path, which is where the reference does it — see the `got == 0` branch in
     * cmd/lc-tunnel/main.c. A comment asserting what a caller does is a claim about a file it cannot
     * see, and this one went unchecked from the first commit until the vendor sieve asked. */
    if (len == 0u || len + 666u > 8192u)
        return -1;

    /* Two for the meta length, two for the session id, then the meta itself. */
    if (out_cap < 4u)
        return -1;
    size_t i = 0;
    out[i++] = 0; /* meta length, patched below */
    out[i++] = 0;
    out[i++] = 0; /* Mux session id: one stream, one session */
    out[i++] = 0;

    if (out_cap < i + 3u)
        return -1;
    if (first) {
        out[i++] = LC_XUDP_STATUS_NEW;
        out[i++] = 0x01u; /* option: a payload follows */
        out[i++] = 0x02u; /* network: UDP */
        size_t used = 0;
        if (write_addr(host, port, out + i, out_cap - i, &used) != 0)
            return -1;
        i += used;
        /* Eight bytes naming the client, on the New frame only — see the header for what the node
         * does with them and why zeros are legal but inert. */
        if (addressed) {
            if (out_cap < i + LC_XUDP_GLOBAL_ID)
                return -1;
            if (global_id != NULL)
                memcpy(out + i, global_id, LC_XUDP_GLOBAL_ID);
            else
                memset(out + i, 0, LC_XUDP_GLOBAL_ID);
            i += LC_XUDP_GLOBAL_ID;
        }
    } else {
        out[i++] = LC_XUDP_STATUS_KEEP;
        out[i++] = 0x01u;
        if (addressed) {
            out[i++] = 0x02u; /* network, because the address follows */
            size_t used = 0;
            if (write_addr(host, port, out + i, out_cap - i, &used) != 0)
                return -1;
            i += used;
        }
    }

    /* Everything after the length field itself, which is what `l := eb.Len() - 2` counts. */
    size_t meta = i - 2u;
    if (meta > 0xffffu)
        return -1;
    out[0] = (uint8_t)(meta >> 8);
    out[1] = (uint8_t)meta;

    if (out_cap < i + 2u + len)
        return -1;
    out[i++] = (uint8_t)(len >> 8);
    out[i++] = (uint8_t)len;
    memcpy(out + i, payload, len);
    i += len;

    *out_len = i;
    return 0;
}

int lc_xudp_wrap(int first, const char *host, uint16_t port, const uint8_t global_id[8],
                 const uint8_t *payload, size_t len,
                 uint8_t *out, size_t out_cap, size_t *out_len)
{
    return wrap(first, 1, host, port, global_id, payload, len, out, out_cap, out_len);
}

int lc_xudp_wrap_unaddressed(int first, const char *host, uint16_t port, const uint8_t *payload,
                             size_t len, uint8_t *out, size_t out_cap, size_t *out_len)
{
    /* `if b.UDP != nil` guards the global id on New and the network and address on Keep
     * (vendor/Xray-core/common/xudp/xudp.go:105-119): a datagram without an address of its own
     * gets neither. */
    return wrap(first, 0, host, port, NULL, payload, len, out, out_cap, out_len);
}

int lc_xudp_next(const uint8_t *buf, size_t len,
                 char *host, size_t host_cap, uint16_t *port,
                 const uint8_t **payload, size_t *payload_len, size_t *used)
{
    if (host_cap > 0u)
        host[0] = '\0';
    *port = 0;
    if (len < 2u)
        return 0;
    size_t meta = (size_t)buf[0] << 8 | buf[1];
    /* `if l < 4 { return nil, io.EOF }` (xudp.go:156-158): a meta block with no room for a session
     * id and a status is not a frame — and the reference calls that the END of the stream, not a
     * fault in it. See LC_XUDP_ENDED in the header for why the difference is the whole point. */
    if (meta < 4u)
        return LC_XUDP_ENDED;
    /* Read into one buffer of buf.Size, which refuses a longer read before taking a byte
     * (vendor/Xray-core/common/xudp/xudp.go:159-163, vendor/Xray-core/common/buf/buffer.go:334-339). */
    if (meta > 8192u)
        return -1;
    if (len < 2u + meta)
        return 0;

    /* buf[2],buf[3] are the session id; buf[4] the status, buf[5] the option. */
    uint8_t status = buf[4];
    uint8_t option = buf[5];
    /* The reader accepts Keep (2), treats KeepAlive (4) as something to discard, and calls anything
     * else the end of the stream — `case 2: ... case 4: discard = true; default: return io.EOF`
     * (xudp.go:164-181). New does not arrive from a server.
     *
     * The four is KeepAlive and NOT End: vendor/Xray-core/common/mux/frame.go:19-22 numbers them
     * New 0x01, Keep 0x02, End 0x03, KeepAlive 0x04, so End is the status that falls to `default`
     * and ends the stream. This comment used to call the four "End", which contradicted xudp.h a
     * dozen lines away and
     * would have made the next reader think a session teardown was being silently swallowed. */
    /* ⚠️ AND ANYTHING ELSE IS THE END OF THE STREAM, WHICH IS WHERE End (0x03) LANDS. The reference
     * ends the read rather than failing it — `default: b.Release(); return io.EOF` (xudp.go:164-181)
     * — so a node closing a datagram session in the ordinary way arrives here, not in the refusals
     * above. Answering `-1` made End indistinguishable from corrupt framing, and lc-tunnel then had
     * a comment describing an End frame reaching it with an empty host, on a path that could not
     * execute because this line had already refused the frame. */
    if (status != LC_XUDP_STATUS_KEEP && status != 0x04u)
        return LC_XUDP_ENDED;

    /* THE ADDRESS THIS FRAME CAME FROM, which this used to skip over with the rest of the meta.
     *
     * It is not decoration and it is not optional to a client that carries more than one
     * destination on a stream. A Keep frame states its own address — the writer does the same on
     * this side, and upstream's does too:
     *
     *     eb.WriteByte(2) // Keep
     *     eb.WriteByte(1) // Opt
     *     if b.UDP != nil { eb.WriteByte(2); AddrParser.WriteAddressPort(eb, b.UDP.Address, ...) }
     *                                       (vendor/Xray-core/common/xudp/xudp.go:116-121)
     *
     * That is the whole reason one xudp session can serve every destination a client talks to: the
     * session belongs to the CLIENT, and each frame says where its datagram is going or came from.
     * Skipping it here meant a reply could only ever be attributed to the one destination the
     * stream was opened for, which is why this client USED TO open a stream per destination — the
     * tense matters, because the model it describes is gone and a reader who takes it as current
     * concludes that this parse has no caller that needs it.
     *
     * ONLY FOR KEEP, AND ONLY WHEN THE NETWORK BYTE SAYS UDP — `case 2: if l > 4 && b.Byte(4) == 2
     * { ... AddrParser.ReadAddressPort ... }` (vendor/Xray-core/common/xudp/xudp.go:165-179). Any
     * other network byte is not an error there: the frame goes on with no address. And a
     * KeepAlive's meta is never read at all, so a bad address in one is thrown away with it. This
     * refused the first and parsed the second.
     *
     * Absent is not an error. A Keep with no address, or with one whose network byte is not UDP,
     * reaches the caller with an empty host and decides there. */
    if (status == LC_XUDP_STATUS_KEEP && meta > 4u && buf[6] == 0x02u) {
        size_t got = 0;
        if (read_addr(buf + 7u, buf + 2u + meta, host, host_cap, port, &got) != 0)
            return -1;
    }

    size_t i = 2u + meta;
    /* `if b.Byte(3) == 1` — the option byte IS 1, which is what says a payload follows
     * (vendor/Xray-core/common/xudp/xudp.go:188). Not its low bit: any option other than 1 means
     * no payload there, and the next two bytes are the next frame's length. */
    if (option != 0x01u) {
        *payload = NULL;
        *payload_len = 0;
        *used = i;
        return 1;
    }
    if (len < i + 2u)
        return 0;
    size_t n = (size_t)buf[i] << 8 | buf[i + 1u];
    /* Into the same buffer, cleared: buf.Size again, refused before a byte is read
     * (vendor/Xray-core/common/xudp/xudp.go:187-196). */
    if (n > 8192u)
        return -1;
    if (len < i + 2u + n)
        return 0;

    /* KEEPALIVE IS CONSUMED AND NOT DELIVERED, which is the half of `discard` this had missing.
     *
     * The reference reads the payload either way — it has to, or the next frame starts in the
     * middle of this one — and only then decides: `if !discard { return buf.MultiBuffer{b}, nil }`,
     * so a status-4 frame falls through to `b.Release()` and the loop goes round for the next one
     * (vendor/Xray-core/common/xudp/xudp.go:181-204). `discard` is set by `case 4` alone (:181).
     *
     * This returned the bytes to the caller for status 4 exactly as for Keep, which would have put
     * a KeepAlive's payload into the stream as data. The comment above already said "treats
     * KeepAlive (4) as something to discard" — it described the reference correctly and the code
     * did the other thing.
     *
     * `used` still counts the payload: consuming it is the part that keeps the reader in frame. */
    *payload = (status == LC_XUDP_STATUS_KEEP) ? buf + i + 2u : NULL;
    *payload_len = (status == LC_XUDP_STATUS_KEEP) ? n : 0;
    *used = i + 2u + n;
    return 1;
}
