#include "h2/xhttp.h"

#include "h2/frame.h"
#include "h2/hpack.h"
#include "core/gomap.h"
#include "core/rnd.h"
#include "quic/pad.h"
#include "reality/browser.h"

#include <stdio.h>
#include <string.h>

/* Credit is returned once a quarter of the window has been spent. Per frame it would be one packet
 * of overhead for every packet of payload; left until the window is empty it would be a stall. */
#define CREDIT_AT (LC_XHTTP_STREAM_WINDOW / 4u)

long lc_xhttp_open(lc_xhttp *x, const char *host, const char *path, uint8_t *out, size_t cap)
{
    memset(x, 0, sizeof *x);
    x->stream = 1u;
    x->send_stream = 65535; /* until the peer's SETTINGS says otherwise, which is the default */
    x->peer_initial_window = 65535u;
    x->send_conn = 65535;

    /* The padding: a run of one letter, in the query string of a URL that goes in `referer`. Its
     * length is drawn from the same range Xray uses when nothing is configured. */
    uint32_t pad_len = 0;
    if (lc_pad_draw(LC_XHTTP_PAD_MIN, LC_XHTTP_PAD_MAX, &pad_len) != 0)
        return -1;

    char slashed[128];
    size_t plen = strlen(path);
    if (plen == 0 || plen + 2u > sizeof slashed)
        return -1;
    /* The trailing slash the reference sends and the configuration does not mention. */
    snprintf(slashed, sizeof slashed, "%s%s", path, path[plen - 1u] == '/' ? "" : "/");

    char referer[LC_XHTTP_PAD_MAX + 256u];
    int  n = snprintf(referer, sizeof referer, "https://%s%s?x_padding=", host, slashed);
    if (n < 0 || (size_t)n + pad_len + 1u > sizeof referer)
        return -1;
    memset(referer + n, 'X', pad_len);
    referer[(size_t)n + pad_len] = '\0';

    /* :scheme is not optional. RFC 9113 requires it on every request that is not CONNECT, and a Go
     * server answers one without it by killing the stream — silently, as far as the client can
     * tell: the connection stays up, the request is never routed, and nothing is logged.
     *
     * AND THE BROWSER THIS REQUEST CLAIMS TO BE, which was missing entirely — five fields went out
     * where the reference sends eighteen, with no User-Agent at all. An HTTP/2 POST to a CDN with no
     * User-Agent is not a request any browser or any library makes; it is a hand-written client, and
     * a transport whose whole purpose is to look like a page fetching from its own origin cannot
     * afford to be the one request on the host that has no browser behind it.
     *
     * splithttp asks for these by name on every request it builds: GetRequestHeader ends in
     * `utils.TryDefaultHeadersWith(header, "fetch")`
     * (vendor/Xray-core/transport/internet/splithttp/config.go:56-63), and that fills in the Chrome
     * identity plus the "fetch" variant unless the
     * user configured a User-Agent of their own. This client configures none, so it gets all of
     * them — the same identity the REALITY spider wears, from the same anchor, differing only in
     * the variant, exactly as one Xray process presents one Chrome for both kinds of request. */
    lc_browser b;
    if (lc_browser_chrome_anchored(&b, LC_BROWSER_FETCH) != 0)
        return -1;

    lc_hpack_field fields[6u + LC_BROWSER_HEADERS];
    unsigned       nf = 0;
    fields[nf++] = (lc_hpack_field){ ":authority", host };
    fields[nf++] = (lc_hpack_field){ ":method", "POST" };
    fields[nf++] = (lc_hpack_field){ ":path", slashed };
    fields[nf++] = (lc_hpack_field){ ":scheme", "https" };

    /* req.Header, in the order splithttp fills it, which is what the walk below starts from: the
     * browser's thirteen from GetRequestHeader (splithttp/config.go:56-63), then the padding
     * Referer (FillStreamRequest, splithttp/config.go:301-323), then Content-Type (:326-328). */
    lc_hpack_field hdr[2u + LC_BROWSER_HEADERS];
    unsigned       nh = 0;
    for (unsigned i = 0; i < b.count; i++)
        hdr[nh++] = (lc_hpack_field){ b.header[i].name, b.header[i].value };
    hdr[nh++] = (lc_hpack_field){ "referer", referer };
    /* `if request.Body != nil && !c.NoGRPCHeader` — a stream-up request carries a body, and
     * noGRPCHeader is off unless configured
     * (vendor/Xray-core/transport/internet/splithttp/config.go:326-328). The value is a lie the
     * reference tells on purpose: nothing here speaks gRPC, but a POST that says it does is a shape
     * intermediaries already expect to be long-lived and streaming. */
    hdr[nh++] = (lc_hpack_field){ "content-type", "application/grpc" };

    /* AND THEN WALKED AS GO WALKS A MAP, because the reference does not choose an order — it has
     * none to choose. Go writes the request's ordinary headers with `for k, vv := range req.Header`
     * (vendor/x-net/internal/httpcommon/request.go:156), and a fixed order is not "a different order
     * from the reference" but a different KIND of thing: it separates on the second request.
     *
     * ⚠️ AND NOT A SHUFFLE, which is what stood here: a Fisher-Yates over the thirteen and two,
     * every order equally likely. A Go map walk is not that. Fifteen keys live in a hashed table of
     * thirty-two slots read from a random slot onwards, so neighbours in the table stay neighbours
     * in the walk far more often than a shuffle allows, and some orders a shuffle produces Go never
     * does. core/gomap models the walk and test/gomap holds it to Go's own maps.
     *
     * The four pseudo-headers are NOT in the walk and must not be: they are written by name, in the
     * order :authority, :method, :path, :scheme (same file, :138-146), before the map is touched.
     * A draw that fails is a request that does not go out, rather than one in a fixed order. */
    unsigned order[LC_GOMAP_KEYS];
    if (lc_gomap_fresh_walk(nh, order) != 0)
        return -1;
    for (unsigned i = 0; i < nh; i++)
        fields[nf++] = hdr[order[i]];

    uint8_t block[LC_XHTTP_PAD_MAX + 1024u];
    long    blen = lc_hpack_encode(fields, nf, block, sizeof block);
    if (blen < 0)
        return -1;

    size_t off = 0;
    size_t w = lc_h2_preface(out, cap);
    if (w == 0)
        return -1;
    off += w;

    w = lc_h2_settings(out + off, cap - off, LC_XHTTP_STREAM_WINDOW);
    if (w == 0)
        return -1;
    off += w;

    w = lc_h2_window_update(out + off, cap - off, 0, LC_XHTTP_CONN_CREDIT);
    if (w == 0)
        return -1;
    off += w;
    x->owed_conn = 0;

    /* Not END_STREAM: the request body is the upload channel and stays open. */
    w = lc_h2_headers(out + off, cap - off, x->stream, block, (size_t)blen, 0);
    if (w == 0)
        return -1;
    off += w;

    return (long)off;
}

size_t lc_xhttp_data(lc_xhttp *x, size_t len, uint8_t *out, size_t cap, size_t *carried)
{
    *carried = 0;
    if (x->ended || len == 0)
        return 0;

    /* Whichever of the two runs out first, and never more than one frame's worth. */
    int64_t room = x->send_stream < x->send_conn ? x->send_stream : x->send_conn;
    if (room <= 0)
        return 0;
    if ((uint64_t)room > (uint64_t)len)
        room = (int64_t)len;
    if (room > (int64_t)LC_H2_MAX_FRAME)
        room = (int64_t)LC_H2_MAX_FRAME;

    size_t w = lc_h2_data_header(out, cap, x->stream, (size_t)room, 0);
    if (w == 0)
        return 0;

    x->send_stream -= room;
    x->send_conn -= room;
    *carried = (size_t)room;
    return w;
}

size_t lc_xhttp_credit(lc_xhttp *x, uint32_t n, uint8_t *out, size_t cap)
{
    x->owed_stream += n;
    x->owed_conn += n;
    if (x->owed_stream < CREDIT_AT)
        return 0;

    size_t off = 0;
    size_t w = lc_h2_window_update(out, cap, x->stream, x->owed_stream);
    if (w == 0)
        return 0;
    off += w;
    x->owed_stream = 0;

    w = lc_h2_window_update(out + off, cap - off, 0, x->owed_conn);
    if (w == 0)
        return off;
    x->owed_conn = 0;
    return off + w;
}

int lc_xhttp_read(lc_xhttp *x, const uint8_t *in, size_t len, lc_xhttp_event *ev)
{
    memset(ev, 0, sizeof *ev);

    lc_h2_hd hd;
    if (lc_h2_get_header(in, len, &hd) != 0)
        return len < LC_H2_HEADER ? 0 : -1;
    if (len < LC_H2_HEADER + hd.len)
        return 0;

    const uint8_t *payload = in + LC_H2_HEADER;
    ev->consumed = LC_H2_HEADER + hd.len;

    switch (hd.type) {
    case LC_H2_DATA:
        /* Padding on a DATA frame is a length byte and then that many bytes at the end. This client
         * never sends one; the peer may, and a reader that ignored the flag would hand the padding
         * to the caller as if it were payload. */
        if (hd.flags & 0x08u) {
            if (hd.len == 0 || payload[0] >= hd.len)
                return -1;
            ev->body = payload + 1;
            ev->body_len = hd.len - 1u - payload[0];
        } else {
            ev->body = payload;
            ev->body_len = hd.len;
        }
        if (hd.flags & LC_H2_END_STREAM)
            x->ended = 1;
        return 1;

    case LC_H2_HEADERS:
        /* The answer's own headers. Their contents decide nothing here — the status is not a
         * tunnel-level signal, and the body is the tunnel — but the frame has to be stepped over. */
        x->got_response = 1;
        if (hd.flags & LC_H2_END_STREAM)
            x->ended = 1;
        return 1;

    case LC_H2_SETTINGS:
        if (hd.flags & LC_H2_ACK)
            return 1;
        /* The one setting that changes what this client may do. Every stream's window moves by the
         * difference, not to the value — a peer that raises it mid-connection is adding to what was
         * already granted. */
        for (uint32_t i = 0; i + 6u <= hd.len; i += 6u) {
            uint16_t id = (uint16_t)((uint16_t)payload[i] << 8 | payload[i + 1]);
            uint32_t v = (uint32_t)payload[i + 2] << 24 | (uint32_t)payload[i + 3] << 16 |
                         (uint32_t)payload[i + 4] << 8 | payload[i + 5];
            if (id == 0x4u) {
                if (v > 0x7fffffffu)
                    return -1;
                /* Moved by the difference from what the peer last announced, not from the default.
                 * A peer that sends SETTINGS twice — which nothing forbids — would otherwise have
                 * the first change counted again in the second, and the window this client believes
                 * it has would drift further from the truth with every one. */
                x->send_stream += (int64_t)v - (int64_t)x->peer_initial_window;
                x->peer_initial_window = v;
            }
        }
        ev->reply_len = lc_h2_settings_ack(ev->reply, sizeof ev->reply);
        return 1;

    case LC_H2_WINDOW_UPDATE: {
        if (hd.len != 4u)
            return -1;
        uint32_t incr = ((uint32_t)payload[0] & 0x7fu) << 24 | (uint32_t)payload[1] << 16 |
                        (uint32_t)payload[2] << 8 | payload[3];
        if (incr == 0)
            return -1;
        /* RFC 9113 §6.9.1: a flow-control window that a WINDOW_UPDATE would push past 2^31-1 is an
         * error, not a saturating add. Symmetric to the SETTINGS_INITIAL_WINDOW_SIZE check above. */
        if (hd.stream == 0) {
            if (x->send_conn + (int64_t)incr > 0x7fffffff)
                return -1;
            x->send_conn += incr;
        } else {
            if (x->send_stream + (int64_t)incr > 0x7fffffff)
                return -1;
            x->send_stream += incr;
        }
        return 1;
    }

    case LC_H2_PING:
        if (hd.len != 8u)
            return -1;
        if (!(hd.flags & LC_H2_ACK)) {
            /* Answered with the same eight bytes, which is the whole of what a ping asks for. A
             * client that does not answer is one the peer eventually stops waiting for. */
            size_t w = lc_h2_put_header(ev->reply, sizeof ev->reply, 8u, LC_H2_PING, LC_H2_ACK, 0);
            if (w != 0 && sizeof ev->reply >= w + 8u) {
                memcpy(ev->reply + w, payload, 8u);
                ev->reply_len = w + 8u;
            }
        }
        return 1;

    case LC_H2_RST_STREAM:
    case LC_H2_GOAWAY:
        /* The peer has finished with this stream, or with the connection. Either way there is
         * nothing further to carry, and pretending otherwise would leave the caller waiting. */
        x->ended = 1;
        return 1;

    default:
        /* Unknown types are stepped over rather than refused: that is what RFC 9113 asks of an
         * endpoint, and it is what lets the protocol gain a frame type without breaking this. */
        return 1;
    }
}
