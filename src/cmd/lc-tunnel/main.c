/* lc-tunnel — the plane itself: LAN traffic in, tunnel out.
 *
 * Accepts on a TPROXY listener, opens one tunnel per connection and pumps both directions. One
 * tunnel per connection rather than one multiplexed link, because Vision's direct copy only works
 * when a proxied stream maps to a whole connection — and that is the difference between 25 and 519
 * Mbit/s on the measured hardware.
 *
 *   lc-tunnel TABLE.fpt NODE PORT SNI PBK SHORTID UUID LISTEN [-t HOST:PORT] [-f FLOW]
 *
 * Without -t the listener is transparent and the target comes from the connection, which is how it
 * runs on a router. With -t every connection goes to a fixed target, which is how the data path is
 * exercised without root or nftables.
 *
 * Nothing blocks. A connection is accepted, its tunnel is started, and the loop carries the TCP
 * connect and the TLS handshake to completion alongside every other connection's traffic. That was
 * not true until recently: the handshake ran to completion inside the accept handler, so one new
 * connection stalled every other for a round trip to the node plus about four milliseconds of key
 * exchange — over half a second of head-of-line blocking for a browser opening twenty at once.
 *
 * Name resolution is synchronous and has no non-blocking form, so it never runs on the loop thread.
 * A node given as an address is parsed once, in main; a node given as a name is looked up per dial,
 * as the reference looks it up, on a thread of its own whose answer the loop is woken for — see
 * net/dial.h. It used to be neither: start_tunnel called getaddrinfo on the loop thread every time
 * a LAN client connected, and then, until 2026-09-29, a name was looked up once at start and kept.
 *
 * ⚠️ SIX THOUSAND LINES IN ONE FILE, ON PURPOSE — DECIDED, NOT NEGLECTED.
 *
 * This sat on a list of debts as "lc-tunnel is not split up", which is a description without a
 * verdict, and this tree has already paid for one of those: a note in tls/record.h that named a
 * difference and stopped there got re-reported as a defect by the vendor sieve and cost an
 * acceptance pass to put back. A reader — human or machine — cannot tell an unmade decision from a
 * made one, so the decision is written here.
 *
 * The measurements that decide it, taken rather than assumed:
 *
 *   HALF OF THIS FILE IS PROSE. 5927 lines, 2926 of them comment — 49%. The code is about three
 *   thousand lines, which is an ordinary size for one program. Splitting would not remove any of
 *   it; it would scatter the explanations, and the explanations are what make the rest navigable.
 *
 *   THE OBVIOUS SEAM IS NOT A SEAM. The Hysteria2 plane looks like a module and is not one: its
 *   1075 lines live in FOURTEEN separate `#if LC_HYSTERIA` regions, and several of them are inside
 *   functions this file cannot give away — the stream teardown inside session_close, three places
 *   in the event loop, its share of the summary. Moving the one big block (865 lines) would leave
 *   two hundred lines of fences behind and buy a file that still has to be read alongside this one.
 *   Making it a real module means callbacks and an exported session type, which is a redesign.
 *
 *   AND THE SAFETY ARGUMENT RESTS ON SINGLE OWNERSHIP. The scratch buffers below are shared by every
 *   connection on the device, and what makes that safe is stated where they are declared: "One
 *   thread, one event handler at a time, and no handler ever suspends holding any of it." The same
 *   goes for the session table. Exporting those through a header to satisfy a line count would put
 *   the one property this program's memory safety depends on behind a declaration instead of behind
 *   a file boundary.
 *
 * WHAT WOULD CHANGE THE ANSWER: a second event loop, or a second thread. Either one breaks the
 * single-owner argument on its own, and at that point the state has to be handed about explicitly
 * anyway — which is the moment to split, and for a reason rather than for a number. */

#include "core/args.h"
#include "fp/fpt.h"
#include "fp/hello.h"
#include "core/portunion.h"
#include "core/rnd.h"
#include "core/worker_event.h"
#include "core/say.h"
#include "reality/spider.h"
#include "reality/paths.h"
#include "h2/frame.h"
/* Generated: which commit this binary was built from. See $(BUILD)/gen/version.h in the Makefile,
 * and the comment there for why it is a header and not a -D on the command line. */
#include "version.h"
#include "net/dial.h"
#include "net/loop.h"
#include "net/reader.h"
#include "net/sock.h"
#include "net/tproxy.h"
#include "tls/client.h"
/* The handshake types, and what the node's records are once the handshake is over — see
 * node_record. */
#include "tls/msg.h"
#include "tls/post.h"
#include "tls/rawin.h"
#include "tls/recopen.h"
#include "tls/alert.h"
#include "vless/vless.h"
#include "vless/xudp.h"
#include "vless/vision.h"

/* Whether this build carries the Hysteria2 plane at all.
 *
 * Left out, it takes ngtcp2, nghttp3 and everything above them with it — three hundred kilobytes
 * against a client that is otherwise sixty-seven, on a device whose whole budget is a megabyte and
 * a half. A household that reaches its node over REALITY should not carry a QUIC stack it will
 * never open, and one that reaches it over Hysteria2 should not carry a fingerprint table.
 *
 * The plane's call sites are written the same either way; only the definitions below differ. That
 * is deliberate — a loop body full of conditional compilation is a loop body where the two
 * configurations drift apart and only one of them is ever run.
 *
 * Required rather than defaulted. It used to default to 1 here, which turned a build system that
 * lost -DLC_HYSTERIA into a build that compiles and is the wrong one — and that is not hypothetical:
 * the OpenWrt recipe passed CFLAGS on make's command line and wiped every flag the top-level
 * makefile adds, this one included. Whichever way the default fell, one of the two packages would
 * have shipped as the other with nothing to show for it. A missing switch is now a compile error,
 * which is the only symptom of this that anybody notices in time. */
#ifndef LC_HYSTERIA
#error "LC_HYSTERIA must be defined to 0 or 1 — see the top-level Makefile; a default here would let a build system that dropped the flag ship the wrong plane"
#endif

#if LC_HYSTERIA
#include "quic/conn.h"
#endif

/* The floor upstream puts under the hop interval — "hop interval must be at least 5 seconds"
 * (vendor/hysteria/extras/transport/udphop/conn.go:117-119). Here rather than taken from conn.h for
 * the same reason -g's ceiling is: the argument parser accepts -j in BOTH builds, and conn.h is only
 * in one of them. The assert below is what keeps the two numbers one number. */
#define HOP_MIN_SECS 5u
#if LC_HYSTERIA
_Static_assert(LC_QCONN_HOP_MIN_MS == HOP_MIN_SECS * 1000u,
               "the argument's floor and the connection's must be the same second");
#endif

/* Outside the switch on purpose: the argument parser accepts -g in both builds, so it needs
 * the one number it bounds the sizes against. Nothing here is linked without the plane — a frame
 * layout and a ceiling. */
#include "quic/gecko.h"
#include "core/wipe.h"
#include "tls/hkdf.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

#ifndef LC_SPIDER_PROFILE
#define LC_SPIDER_PROFILE 0
#endif

#define MAX_TABLE 65536u
#define MAX_REC LC_REC_MAX_WIRE12

/* The two constants Go sizes its records from, derived rather than copied so that the arithmetic is
 * visible: tcpMSSEstimate 1208, minus the 5-byte record header, minus a TLS 1.3 AEAD tag of 16,
 * minus the one encrypted ContentType byte (vendor/utls/conn.go:873-884 and :913-933). The explicit
 * nonce is zero for both TLS 1.3 suites. */
#define LC_RECORD_PAYLOAD_STEP (1208u - 5u - 16u - 1u)
#define LC_RECORD_BOOST_THRESHOLD (128u * 1024u)

/* One TLS record's worth of plaintext, plus room for the framing that goes around it. A queue is
 * sized so that whatever a single read can produce always fits: the pump then never has to hold a
 * half-written record, which is the state that makes a proxy lose bytes. */
/* TWO SIZES, BECAUSE ONLY ONE OF THE TWO QUEUES CAN HOLD A HALF-ARRIVED DATAGRAM.
 *
 * They were one constant, and when the reserve below was added to it every session grew by twice
 * what the fix needed: the reserve exists for the queue going to the LAN, where a partial xudp frame
 * waits for its remainder, and the queue going to the node never holds one — what is in it is
 * already framed and always leaves.
 *
 * The arithmetic is worth writing down, because this device does not have the memory to be casual
 * about it. A session carries both queues, so over two hundred and fifty-six sessions the difference
 * is 256 × 8 451 = 2.2 MB since the reserve holds a datagram of buf.Size (it was 4 355, and 1.1 MB, while it
 * held the other plane's 4 096) — against roughly 18 MB free on the 4A, and every one of those sessions is
 * something a device on the LAN can ask for. Sharing one constant would have spent that on a queue
 * that cannot use it.
 *
 * UP_QUEUE_SIZE is left at exactly what it was, MAX_REC + 2048 = 18 693, and this note used to say
 * that tightening it to what its own guarantee needs — UP_WORST_PER_READ, 9 706 — was a change to
 * make later, with a measurement. The measurement is arithmetic and it says do not:
 *
 *     the gate arms while  q_room >= UP_WORST_PER_READ,  so while  pending <= 18 693 - 9 706 = 8 987
 *     which is 0.93 of one worst-case read
 *
 * A queue sized at the guarantee itself would arm only on an empty queue, so every read would wait
 * for the previous one to leave for the node — uploads serialised one read at a time, on the plane
 * where a read is 8 KB. The natural floor is therefore TWICE the guarantee, 19 412, and 18 693 is
 * already just under it: a second read is admitted once the first has partly drained. There is
 * nothing here to reclaim, and the number that looked arbitrary turns out to be the right size for a
 * reason it never stated. */
#define UP_QUEUE_SIZE (MAX_REC + 2048u)
#define LAN_QUEUE_SIZE (MAX_REC + 2048u + DOWN_PARTIAL_DATAGRAM)

/* AND ON A DATAGRAM SESSION IT MUST ALSO HOLD A HALF-ARRIVED DATAGRAM, which is the part it did not.
 *
 * The download side arms its read only while the LAN queue has a whole record's plaintext free —
 * `q_room(&s->to_lan) >= LC_REC_MAX_PLAINTEXT`, in session_rearm. On a TCP session that is exactly
 * right: whatever is in the queue can always leave for the socket, so room appears by itself.
 *
 * On a UDP session it cannot. A datagram is delivered whole or not at all, so an xudp frame that has
 * only partly arrived STAYS in the queue — and while it sits there it occupies room, and the gate
 * measures room, and the frame needs more bytes to become complete. Queue holds a partial frame, so
 * the read is not armed, so the rest never arrives, so the frame stays partial. The session then sits
 * there until its idle timer, having lost one datagram and said nothing.
 *
 * Measured on the stand before it was understood: a proxied datagram of 3 000 bytes always arrived,
 * one of 3 600 never did, and one of about 3 360 arrived seven times in fifteen. The jitter was the
 * clue — Vision's padding is random, so it decides whether a frame finishes inside the second record
 * or spills into a third. With one shared queue size of MAX_REC + 2048 the gate needed pending ≤ 2 309, and two
 * records of Xray's ramp (1 186 then 2 372) leave 3 495 pending the moment a frame does not fit them.
 *
 * So the queue is sized for the largest partial a legal peer can leave: one xudp frame's framing plus
 * the largest datagram the reference's reader takes, a buffer of buf.Size — the frame's data is read
 * into the same 8192-byte buffer its metadata was, and a longer one fails the read
 * (vendor/Xray-core/common/xudp/xudp.go:159-200). A peer that declares more than that never
 * completes a frame and fills the queue, which q_push refuses and the session ends — the same answer
 * the reference's failed read gives. The Hysteria2 plane's ceiling, 4096, is below it.
 *
 * The meta block is bounded by its own one-byte-per-field shape rather than measured: 255 is more
 * than a session id, a status, an option, a network and an address can be, and the difference costs
 * a quarter of a kilobyte on a queue that is already sixteen. */
/* buf.Size, which is what the REALITY plane's reference reads a datagram into on either side, and the
 * largest datagram its xudp writer carries — see UDP_MAX_DATAGRAM. */
#define XUDP_READ_SIZE 8192u
#define XUDP_MAX_DATAGRAM (XUDP_READ_SIZE - 666u)
#define DOWN_PARTIAL_DATAGRAM (2u + 255u + 2u + XUDP_READ_SIZE)

/* WHAT ONE READ FROM THE CLIENT CAN BECOME ON THE WIRE, and the sentence above was not true of it.
 *
 * The read arms only when this much room is free, and the number used to be READ_CHUNK + 1024 —
 * 9216 — chosen as a round allowance rather than derived from anything. The plaintext first: one
 * read is cut at the last `17 03 03` into at most two pieces, each framed on its own, and the pair
 * does not fit in 9216:
 *
 *     (content + padding) of the head              ≤ LC_VISION_MAX_BODY   = 8171
 *     (content + padding) of a long-padded tail    ≤ LC_VISION_MAX_LONG   = 1399
 *     Vision header on each, and the UUID once     = 2 × 5 + 16            =   26
 *                                                                          ------
 *                                                                            9596
 *
 * The tail is the half that grows: long padding aims at 900..1399 REGARDLESS of how little content
 * it has, so a 276-byte tail leaves as 1399 bytes of body. The head meanwhile is capped at 8171 by
 * lc_vision_pad itself, so the two maxima are reached together — a cut at 7916 does it.
 *
 * ⚠️ AND THEN THE RECORDS, WHICH THIS COUNTED AS TWO. "One read becomes at most TWO records" was
 * written before tls_write cut records the way Go does: the first records of a connection hold
 * 1186, 2372, 3558, 4744 bytes, so 7116 < 8192 puts one full-sized frame into FOUR records and its
 * tail into a fifth. Each record costs its header, the inner type and the tag — 22 bytes — so the
 * reserve was 66 short of a read that happened to be the first large one on a connection, on a queue
 * already full enough to be near the gate. Two writes of 9596 bytes can never take more than five:
 * one write of that much takes four (1186 + 2372 + 3558 < 9596 ≤ … + 4744), and a boundary between
 * two writes can end at most one record early.
 *
 * When a read did not fit, q_push returned -1 and the session was closed: an authenticated, working,
 * mid-upload session, torn down and re-handshaked. The reference reaches the same byte counts and has
 * nowhere to overflow: Xray writes into a pipe that either discards the write or WAITS on a signal
 * (vendor/Xray-core/transport/pipe/impl.go:156-167). We cannot wait — one thread, one loop — so the
 * equivalent is to not read until the worst case fits, which is what this number is for.
 *
 * The UUID is counted although only the first framed piece of a connection carries it: sixteen bytes
 * of reserve is a cheap way to stop the guarantee depending on which write went first. */
#define UP_RECORDS_PER_READ 5u
#define UP_RECORD_COST (LC_REC_HEADER + 1u + LC_AEAD_TAG)
#define UP_WORST_PER_READ                                                                        \
    (LC_VLESS_UUID + 2u * LC_VISION_HEADER + LC_VISION_MAX_BODY + LC_VISION_MAX_LONG +             \
     UP_RECORDS_PER_READ * UP_RECORD_COST)

_Static_assert(LC_RECORD_PAYLOAD_STEP * (1u + 2u + 3u) <
                   LC_VLESS_UUID + 2u * LC_VISION_HEADER + LC_VISION_MAX_BODY + LC_VISION_MAX_LONG &&
               LC_VLESS_UUID + 2u * LC_VISION_HEADER + LC_VISION_MAX_BODY + LC_VISION_MAX_LONG <=
                   LC_RECORD_PAYLOAD_STEP * (1u + 2u + 3u + 4u),
               "one read's plaintext must take exactly four records in one write, or five is wrong");

/* And the first write of a connection, which is the same read with the request header in front of it
 * in the same buffered write — see request_write. The header is at most 296 bytes (a domain of 255,
 * the flow, the account) and request_header refuses anything over 512. */
#define UP_REQUEST_HEADER_MAX 512u
#define UP_WORST_FIRST_WRITE (UP_WORST_PER_READ + UP_REQUEST_HEADER_MAX)

_Static_assert(UP_QUEUE_SIZE >= UP_WORST_FIRST_WRITE,
               "the queue must hold what one read can become, or the reserve below is unreachable");

/* The download side of the same guarantee: a partial datagram plus one more record's plaintext must
 * both fit, or the read gate closes on a queue that cannot drain. See DOWN_PARTIAL_DATAGRAM. */
_Static_assert(LAN_QUEUE_SIZE >= LC_REC_MAX_PLAINTEXT + DOWN_PARTIAL_DATAGRAM,
               "a half-arrived datagram must not close the gate that would finish it");

/* Deliberately smaller than a record. Reading less than the maximum costs a syscall now and then and
 * buys the guarantee above with room to spare after Vision's padding. */
#define READ_CHUNK 8192u


/* HOW LONG ONE CONNECT TO THE NODE MAY TAKE, AND NOTHING ELSE HAS A CLOCK.
 *
 * Xray's system dialer is a net.Dialer with `Timeout: time.Second * 16`
 * (vendor/Xray-core/transport/internet/system_dialer.go:138-143), and that bounds the connect of ONE
 * attempt: DialContext returns when the socket is connected or the sixteen seconds are gone. The
 * REALITY handshake that follows runs under the request's context, `uConn.HandshakeContext(ctx)`
 * (vendor/Xray-core/transport/internet/reality/reality.go:201), and that context carries no deadline
 * of any kind — dokodemo's comes from the inbound worker with a cancel and nothing else. A node that
 * accepts and then says nothing holds the attempt until the kernel gives up on the connection or the
 * node closes it; TCP keepalive (lc_tcp_outbound) is the reference's bound there too.
 *
 * ⚠️ WHAT STOOD HERE WAS CONNECT_MS, FIFTEEN SECONDS FOR THE WHOLE DIAL, and the paragraph above it
 * called that "the reference's shape". It was two differences at once. The budget covered every
 * attempt together, so a slow first connect used up the retries; and it covered the handshake, which
 * the reference never cuts. On a black-holed path the reference makes five connects of sixteen
 * seconds each, with its waits between them; this made one fifteen-second attempt and closed the
 * client. And a handshake the node was slow to answer — measured on router-temp as fifteen parallel
 * connections landing between 2.7 and 3.0 s behind this CPU's queue — was abandoned here at fifteen
 * seconds where the reference waits on. */
#define CONNECT_ATTEMPT_MS 16000u

/* How long the VLESS request waits for the client's first bytes once the tunnel is up:
 * `ReadMultiBufferTimeout(time.Millisecond * 500)` (vendor/Xray-core/proxy/vless/outbound/outbound.go:324).
 * See request_write; `make check-request` holds the number to the vendored line. */
#define REQUEST_WAIT_MS 500u

/* HOW MANY TIMES THE NODE IS DIALLED FOR ONE SESSION, AND HOW LONG IS WAITED AFTER EACH.
 *
 * Both are the reference's. Xray's VLESS outbound wraps the WHOLE dial — the TCP connect and the
 * REALITY handshake, since `dialer.Dial` for `security: reality` ends in `reality.UClient(conn,
 * config, ctx, dest)` (vendor/Xray-core/transport/internet/tcp/dialer.go:96) — in
 *
 *     if err := retry.ExponentialBackoff(5, 200).On(func() error {
 *         conn, err = dialer.Dial(ctx, rec.Destination)
 *         ...
 *                        (vendor/Xray-core/proxy/vless/outbound/outbound.go:190-198)
 *
 * and despite the name the delays are linear: `nextDelay` starts at zero and grows by `delay` each
 * time it is read, and On sleeps it after EVERY failure, the last included
 * (vendor/Xray-core/common/retry/retry.go:23-40, :52-62). So 0, 200, 400 and 600 ms between the five
 * attempts, and 800 ms after the fifth before the request fails and the client's connection closes.
 *
 * ⚠️ EVERY DIAL ERROR IS RETRIED, not only a socket that said no. What Dial returns an error for is a
 * connect that failed or timed out, a handshake the client refused — a certificate that did not verify,
 * an answer it would not accept, each with its alert — a connection the node closed mid-handshake, and
 * a node that answered as a stranger, after the spider has been set going on that connection
 * (vendor/Xray-core/transport/internet/reality/reality.go:207-299). All of them go round again. This
 * retried only the socket failures, and called the rest "an answer, which dialling again would put to
 * the same node four more times" — which is exactly what the reference does, four more times.
 *
 * And nothing gates a dial across the device. A process-wide ladder once held every new connection
 * back after failures here; the reference has none on this plane. */
#define DIAL_TRIES   5u
#define DIAL_STEP_MS 200u

/* GRAVESTONE: SPIDER_MS lived here — three seconds, "how long the fetch after a refused
 * authentication may run before the session is closed anyway".
 *
 * Its comment argued that the reference bounds this with a goroutine and a garbage collector and
 * that something therefore had to end it here. The stand tools/vendorcap/spiderlife measured what
 * the reference actually does — nothing ends it, `// Do not close the connection` — and what this
 * client did: it closed at END_STREAM, ten to twenty milliseconds in, so the three seconds never
 * bounded anything and the comment described neither side. The session now lives until the far end
 * ends it; see where ST_SPIDER is entered. */

/* HOW LONG A TUNNEL DIALLED AHEAD OF NEED IS GOOD FOR, AND HOW LONG THE NODE WAITS FOR IT — two
 * numbers from two ends of the reference, and they do not agree.
 *
 * A pre-opened connection has finished the REALITY handshake and has not yet sent a VLESS request.
 * On the other side that is a connection sitting in the inbound's request read, and that read has a
 * deadline:
 *
 *     if err := connection.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake))
 *                            (vendor/Xray-core/proxy/vless/inbound/inbound.go:280)
 *
 * with `Handshake: time.Second * 60` in SessionDefault
 * (vendor/Xray-core/features/policy/policy.go:130). So sixty seconds is the whole window a stock
 * node gives before it closes such a connection.
 *
 * ⚠️ AND THE REFERENCE CLIENT HOLDS ITS CONNECTIONS FOR TWICE THAT, WHICH IS COPIED, NOT CORRECTED.
 * The pool's two numbers are these two lines:
 *
 *     h.preConns <- &ConnExpire{Conn: conn, Expire: time.Now().Add(time.Minute * 2)} // TODO: customize & randomize
 *     time.Sleep(time.Millisecond * 200)                                             // TODO: customize & randomize
 *                    (vendor/Xray-core/proxy/vless/outbound/outbound.go:170-171)
 *
 * A connection is good for two minutes from the moment its dial finished, and a dialler that has
 * handed one over waits 200 ms before it dials the next. So a connection taken in its second minute
 * has usually been closed by a stock node already, and the request written on it fails — in the
 * reference exactly as here. This file held 25-35 s of its own for a while, drawn at random; that was
 * a correction of the reference, and this is a client of it. check-pool holds both numbers to the
 * lines above. */
#define SPARE_EXPIRE_MS 120000u
#define SPARE_SLEEP_MS  200u

/* The most `-P` takes. See the option. */
#define POOL_MAX 4u

/* How long the QUIC handshake may go without a packet from the node before it is abandoned.
 *
 * The reference's own number: `DefaultHandshakeIdleTimeout = 5 * time.Second`
 * (vendor/quic-go/internal/protocol/params.go:97). hysteria sets no handshake timeout of its own —
 * quic-go's default is what every hysteria client uses — so this is the value, not a choice.
 *
 * And the handshake as a whole may take twice that, whatever arrives: `handshakeTimeout()` is
 * `2 * c.HandshakeIdleTimeout` (vendor/quic-go/config.go:17-18), checked against the connection's
 * creation beside the idle one (vendor/quic-go/connection.go:887-892). Both end the connection in

 * silence — see `silent` in quic/conn.h. The authentication that follows has no clock at all:
 * RoundTrip waits on the connection (vendor/hysteria/core/client/client.go:133). */
#define LC_HY_HANDSHAKE_IDLE_MS 5000u
#define LC_HY_HANDSHAKE_MS (2u * LC_HY_HANDSHAKE_IDLE_MS)

/* Sixty seconds, which is the node's own number: defaultUDPIdleTimeout in
 * vendor/hysteria/core/server/config.go:24.
 *
 * It was fifteen, and fifteen against the node's sixty is the wrong side of a mismatch — we forget a
 * session the node still holds, so the next datagram from that client opens a NEW session, and the
 * node answers it from a new port. For anything that survives a pause, which is every HTTP/3
 * connection a browser keeps, that is a broken flow rather than a tidy-up; and the datagram share on
 * this router is 100 %. The old note below was written when this was sixty for a different reason
 * and cut to fifteen for a good one — a session table that a burst of fresh source ports could
 * exhaust — but that argument is answered by the table's own bounds, not by disagreeing with the
 * node about how long a session lives.
 *
 * The Hysteria2 plane's only. A REALITY datagram session is let go by the rule of Xray's UDP inbound —
 * see UDP_CHECK_MS. */
#define UDP_IDLE_MS 60000u

/* THE REALITY PLANE'S CLOCKS, WHICH ARE XRAY'S SESSION POLICY AND ONE TIMER, NOT FOUR DEADLINES.
 *
 *     ConnectionIdle: time.Second * 300,
 *     UplinkOnly:     time.Second * 1,
 *     DownlinkOnly:   time.Second * 1,
 *                    (vendor/Xray-core/features/policy/policy.go:125-133)
 *
 * The VLESS outbound makes one ActivityTimer per connection with ConnectionIdle, and each copy moves
 * it to the other number when it ends: the uplink with `defer timer.SetTimeout(DownlinkOnly)`, the
 * downlink with `defer timer.SetTimeout(UplinkOnly)`
 * (vendor/Xray-core/proxy/vless/outbound/outbound.go:293-299, :310, :370). When the timer fires the
 * context is cancelled and the connection closed; when both copies end first, it is closed then.
 * Direct copy moves it to a day for as long as the kernel is splicing
 * (vendor/Xray-core/proxy/proxy.go:774).
 *
 * The timer is not a deadline. SetTimeout marks activity and checks at once, which consumes the mark,
 * and then checks every `timeout`: it fires at the first check that finds no activity since the one
 * before (vendor/Xray-core/common/signal/timer.go:26-76,
 * vendor/Xray-core/common/task/periodic.go:27-71). So a quiet connection goes exactly `timeout`
 * after the SetTimeout, and one that was active after it goes between one and two `timeout`s after
 * its last activity. Activity is each MultiBuffer
 * the uplink copies (vendor/Xray-core/common/buf/copy.go:27-32) and each non-empty read of the downlink
 * (vendor/Xray-core/proxy/vless/encoding/encoding.go:188-191) — not the request's first write, which is
 * made before the copy starts, and not the spliced bytes, which the process never sees.
 *
 * ⚠️ WHAT STOOD HERE WAS DOWNLINK_ONLY_MS AS A DEADLINE, AND A HALF-CLOSE PASSED ON AS A FIN. Neither
 * is the reference: it never shuts a direction of either socket, so the node saw our FIN the moment the
 * client stopped sending, the client saw its FIN the moment the node did, and the close_notify written
 * at the end went into a socket already shut for writing — `write` returned -1 on every ordinary HTTP
 * exchange on the wireshape stand, where the reference's 24-byte close_notify leaves two seconds after
 * the last byte. And no stream was ever let go for being idle: an idle connection lived as long as its
 * peers did, where the reference ends it after five minutes. */
#define CONNECTION_IDLE_MS 300000u
#define UPLINK_ONLY_MS 1000u
#define DOWNLINK_ONLY_MS 1000u
#define SPLICE_IDLE_MS (24u * 3600u * 1000u)

/* HOW XRAY'S UDP INBOUND LETS A DATAGRAM SESSION GO: a checker every minute that closes any session
 * with no activity for more than two minutes, in whole seconds —
 *
 *     w.checker = &task.Periodic{Interval: time.Minute, Execute: w.clean}
 *     if nowSec-atomic.LoadInt64(&conn.lastActivityTime) > 2*60 { … conn.Close() }
 *                    (vendor/Xray-core/app/proxyman/inbound/worker.go:387-410, :423-426)
 *
 * so a quiet session goes between two and three minutes after it last moved, and closing it cancels
 * the outbound's context at once (`c.cancel()`, :225-232). Activity is a datagram arriving, the
 * outbound taking what the pipe holds and an answer written back (:285, :310, :195-223). The checker
 * starts with the first session, runs at once when it does, and stops on a pass that STARTS with none
 * left (:330, :392-393) — the pass that closes the last one keeps it running for one more minute. Sixty seconds of silence ended a session here, which cut a pause the reference
 * rides out. */
#define UDP_CHECK_MS 60000u
#define UDP_IDLE_S 120u

/* THE LARGEST DATAGRAM, WHICH IS A DIFFERENT NUMBER ON EACH PLANE because each plane's reference has
 * its own.
 *
 * On the REALITY plane Xray's UDP inbound reads each datagram into a buffer of buf.Size
 * (vendor/Xray-core/transport/internet/udp/hub.go:99-109) and xudp's PacketWriter drops any whose
 * `length+666 > buf.Size` (vendor/Xray-core/common/xudp/xudp.go:99-102): 7526 bytes are carried, a
 * longer one read shortened to 8192 or not is dropped without a word. This client dropped everything
 * over 4096 there, which is the other plane's number — a datagram between the two, a large DNSSEC
 * answer's question or a jumbo QUIC packet, went through the reference and not through this.
 *
 * On the Hysteria2 plane what follows holds. The framing allows sixty-five thousand, the
 * reply queue holds eighteen; accepting what cannot be held is how a session dies mid-stream
 * instead of refusing cleanly. Four kilobytes covers EDNS0 and every QUIC packet.
 *
 * It said that while the socket read into two kilobytes, so the sentence was false by half: a
 * three-kilobyte DNSSEC answer was refused by the read with a message quoting 2048, and the check
 * against this number below could never fire. Meanwhile every session carried a four-kilobyte
 * `pend` of which half was unreachable — two hundred and fifty-six sessions, half a megabyte.
 *
 * One number now, used by the buffer that has to hold it, and asserted equal to what the node
 * accepts: LC_HY_UDP_MAX is the ceiling on the other side of the tunnel, and a client that reads
 * more than the node will carry only moves the drop to where it is harder to see. */
#define UDP_MAX_DATAGRAM 4096u

/* The reserve the LAN queue keeps for a half-arrived datagram is sized from this and must not fall
 * behind it — see DOWN_PARTIAL_DATAGRAM for what closes when it does. Asserted here rather than
 * there because that is where the number it depends on exists. */
_Static_assert(DOWN_PARTIAL_DATAGRAM >= 2u + 255u + 2u + UDP_MAX_DATAGRAM &&
                   DOWN_PARTIAL_DATAGRAM >= 2u + 255u + 2u + XUDP_READ_SIZE,
               "the partial reserve must cover the largest datagram either plane accepts");

#if LC_HYSTERIA
/* Only where there is a node to carry them: the REALITY build has no Hysteria header and proxies no
 * datagrams, so this compares against a number that does not exist there. Found by check-builds,
 * which is the only reason the plane-less build is ever compiled. */
_Static_assert(UDP_MAX_DATAGRAM == LC_HY_UDP_MAX,
               "what this reads and what the node carries have to be one number");
#endif

/* ⚠️ DATAGRAM SESSIONS HAVE NO CEILING, as the reference's have none — and there were two here.
 *
 * Half of a 256-session table for datagrams, and thirty-two per host on the LAN, so that one host
 * asking from a fresh source port every time — a stub resolver does — could not take the router
 * from everything else. What multiplies sessions depends on the plane: on REALITY a session is the
 * client's and carries every address it talks to, so the source port multiplies them; on Hysteria2
 * it is a (src, dst) pair, as the reference's transparent mode makes it, so the destination does
 * too, and thirty-two per host meant thirty-two destinations at once. The reference refuses
 * neither. Xray's UDP inbound opens a connection for every source it hears from
 * (vendor/Xray-core/app/proxyman/inbound/worker.go:280-311), hysteria's tproxy a session for every
 * pair (vendor/hysteria/app/internal/tproxy/udp_linux.go:35-44), and neither counts them. The
 * thirty-third answer a console or a browser on HTTP/3 was waiting for went unanswered here and
 * nowhere else.
 *
 * What bounds them now is what bounds the reference: memory, which session_new asks for before every
 * session, and descriptors, raised at start the way Go raises them (see main). */

/* THE HALF-CLOSE RULE ON THE HYSTERIA2 PLANE, WHICH IS UPSTREAM'S AND HAS NO TIMER.
 *
 * Thirty lines stood here specifying the opposite: that a client which shuts its write side still
 * gets its reply delivered, bounded by a stall timer, and that upstream's rule — close when either
 * direction ends — is "a smaller client and a worse one". They described `LC_STALL_MS` and the
 * deadline fields it hung off. Neither exists; `grep -rn LC_STALL_MS src/` matched that comment and
 * nothing else. The code does what the paragraph called worse: the reader thread marks the client's
 * end (net/reader.c), and hy_send_up ends the session once everything the client sent has been
 * passed on.
 *
 * That is deliberate and it is the reference:
 *
 *     closeErr = <-copyErrChan
 *                     (vendor/hysteria/app/internal/redirect/tcp_linux.go:69-79)
 *
 * — two io.Copy goroutines and one channel, returning as soon as EITHER direction ends, with the
 * deferred closes taking both. No timer anywhere in it, and nothing counted.
 *
 * The removal happened for a measured reason, recorded at the client-EOF branch of the event loop
 * (which is REALITY's now, but still carries the story): the waits this comment
 * specified were being read as evidence that the NODE had failed, and three of them inside thirty
 * seconds threw away the QUIC connection carrying every other session — about twenty times an hour
 * on a live router, every one of them an ordinary keep-alive that had gone quiet. The mechanism
 * manufactured the fault it was written to detect.
 *
 * On the REALITY plane the half-close does not end the session, because there the reference is
 * Xray, whose copies end one direction without ending the other; but it is not passed on either —
 * no socket is shut anywhere in this file. The client's end only moves the timer to
 * DOWNLINK_ONLY_MS, which is that plane's bound and Xray's own number. The two planes differ here
 * because their references do. */

/* What the data path actually did, counted rather than timed.
 *
 * The device says where the time goes only in the coarsest terms: on twenty megabytes this client
 * spends 2080 ticks in its own code against 363 in the kernel, while a relay that only copies bytes
 * spends none of the former and moves the same data seven times faster. Somewhere between those two
 * numbers is work being done per record, and the way to find it is to know how many records there
 * were — a timer around each one would cost more than the record.
 *
 * Increments only, on paths that already touch the data. The summary is printed when asked for with
 * SIGUSR1, not on a schedule: a counter nobody reads costs an add, a counter printed every second
 * costs a decision about when. */
static struct {
    uint64_t rec_in, bytes_in;   /* records unprotected, and their plaintext */
    uint64_t rec_out, bytes_out; /* records sealed, and what went into them */
    uint64_t reads_up, reads_lan;
    /* Times a client's bytes were offered to a stream of a connection that no longer exists, and
     * refused. It counts a RACE rather than a fault: hy_turn closes sessions of a past generation,
     * but it runs at the end of a turn and the read that offers those bytes runs at the start of
     * the next, so between a reconnect and that reaping there is a window. The guard in hy_send_up
     * makes the window harmless; this says whether it is ever entered at all.
     *
     * ⚠️ AND IT IS NOT PRINTED WHILE IT IS ZERO, which is the opposite of what stood here on the day
     * it was added ("a zero here is worth printing… it CAN move on this plane"). That was true about
     * the counter and wrong about the summary: this block is poked every fifteen minutes by cron on
     * the routers and syslog is a 128 KB ring, so a line that says zero for months is a line that
     * shortens how far back anything can be read — measured at 688 of 1097 lines within a day of
     * adding it. It is folded into the write-loop line when it is not zero, and costs nothing when
     * it is. Read 0 from its absence, not from a line. */
    uint64_t up_stale_gen;
    /* `vision_pad` stood here beside it and was incremented by nothing and printed by nothing — a
     * field named after a measurement that was never taken. Gone rather than wired up: padding is
     * already visible where it matters, and a counter whose name promises a number the summary
     * cannot show is the same fault as a header promising a check that does not exist. */
    uint64_t vision_frames;
    /* Records handed to the threads that open them ahead, and of those, how many were answered by
     * them — see tls/recopen.h. DIVERGES: O3. */
    uint64_t rec_handed, rec_ahead;
    uint64_t compactions;   /* queue memmoves, which copy everything still in flight */
    uint64_t direct_bytes;  /* moved by splice, never touched by this process */
    uint64_t copied_bytes;  /* moved raw but through a buffer here, when no pipe was had */
    /* ⚠️ THE OTHER HALF OF "DIRECT", AND IT WAS COUNTED BY NOTHING AT ALL.
     *
     * Vision stops sealing in BOTH directions, not one: downstream turns into a splice, and upstream
     * turns into a plain q_push of the inner connection's own TLS — see push_up_reshaped. The
     * downstream half has had `direct_bytes` since the beginning; the upstream half went out with no
     * counter on the path, so every byte of it was invisible.
     *
     * Measured, not reasoned about: 20 971 520 bytes were pushed through a live router and the
     * summary reported 20 014 across all four workers — a thousandth of what moved. The tell was
     * `reads lan 2572` beside `chunks out 4 (3848 bytes)`: two and a half thousand reads off the LAN
     * socket, four records to show for them.
     *
     * Kept apart from direct_bytes rather than added into it, because they are not the same work and
     * the difference is the whole point of the line they end up on: a splice never touches this
     * process, while this one is a copy into a queue. Someone deciding what a box can carry needs to
     * see which of the two it is doing. */
    uint64_t direct_up_bytes;
    uint64_t pipes_armed, pipes_failed;
    /* Datagram sessions turned away because the flow does not carry the reference's allowUDP443.
     * Counted rather than silent: with the plain Vision spelling this is EVERY intercepted QUIC
     * flow, and an operator who set udp_port and sees no datagram traffic is owed the reason. */
    uint64_t udp443_refused;
    /* ⚠️ INTERCEPTED DATAGRAMS THAT ARRIVED WITHOUT THE ADDRESS THEY WERE SENT TO, and which are
     * therefore dropped. Counted for the reason the line above is: silence is the symptom either
     * way, and an operator staring at a resolver that never answers is owed which of the two it is.
     *
     * lc_udp_recv recovers the original destination from a control message; when the walk finds
     * none it leaves the address empty and the loop drops the datagram. The realistic cause is the
     * socket option not being in effect — IP_RECVORIGDSTADDR and its v6 twin are set in
     * lc_udp_listen, so this counting anything at all means the listener is not what this build
     * thinks it is. That is a configuration fault, and it used to present as UDP simply not working
     * with nothing written down anywhere.
     *
     * Not a `note` per datagram: the failure is systematic rather than occasional, so a line each
     * time would bury the log of a router that is otherwise fine. */
    uint64_t udp_no_dst;
    /* Datagrams, counted apart from streams because they are the one thing that can never take the
     * cheap path. Vision hands a stream to the kernel once it has recognised TLS inside it, and from
     * then on those bytes cost nothing here; a datagram is not a stream and never qualifies, so
     * every one of them is encrypted and decrypted in this process.
     *
     * Which makes this ratio the number a deployment decision hangs on: it says how much of the
     * traffic can never be made cheaper by anything except sending less of it. On a box without AES
     * instructions the difference between the two paths is more than tenfold. */
    uint64_t udp_bytes_up, udp_bytes_down;

    /* How long the person waited for a tunnel to be ready, in buckets, plus the worst one seen.
     *
     * Buckets rather than an average because the average of "mostly instant, occasionally a
     * timeout" describes neither: what a deployment decision needs is how OFTEN the wait was long.
     * See `began_ms` on the session for why this exists at all — counting refusals measured the
     * budget instead of the experience, and the two move in opposite directions.
     *
     * The boundaries are the ones a person notices: a quarter second is imperceptible, a second is
     * a pause, three is "is it broken", and above that they have already reached for reload. */
    uint64_t open_under_250, open_under_1s, open_under_3s;
    /* Above three seconds the buckets get finer, because that is the range a budget would be cut
     * into and the coarse version could not answer the question. "Over 3s: 15" was read as an
     * argument for cutting the dial budget to three — until it was noticed that those fifteen were
     * SUCCESSES, and cutting there would have abandoned every one of them. Whether that is a loss
     * depends on where inside the range they sit: at 3.2 seconds a retry is cheaper than waiting,
     * at 11 it means the connection was never going to be quick and the wait bought the only
     * outcome available. */
    uint64_t open_under_5s, open_under_10s, open_over_10s;
    uint64_t open_worst_ms;
    /* Refusals, kept beside the waits so the pair can never again be read apart: a rise here with a
     * fall there is the budget working, not failing. */
    uint64_t gave_up_connecting, gave_up_handshake;
    /* ⚠️ AND THE DIALS THAT FAILED WITHOUT WAITING, WHICH NEITHER OF THE TWO ABOVE CAN SHOW.
     *
     * Both of those are incremented in one place, the deadline sweep, so both can only ever mean
     * "the budget ran out". A connect that comes back with ECONNREFUSED or ENETUNREACH ends
     * somewhere else entirely — the loop's error branch and the SO_ERROR check below it — where it
     * says its line and is counted by nothing. So the summary showed a node
     * refusing every dial instantly and a node answering every one perfectly with the SAME two
     * zeroes, and the difference between them lived only in lines nobody adds up.
     *
     * That is not a cosmetic gap: this was the number the one-attempt verdict at ST_CONNECTING hung
     * on. A retry converts fast failures and nothing else, and the evidence for that verdict was a
     * counter that cannot tell a fast failure from a hang. The verdict is gone since 2026-09-07 —
     * the reference retries and so does this — but the counter keeps its meaning: it counts
     * ATTEMPTS that came back with an error, so with five tries per session it can now exceed the
     * number of sessions, and that is what it should do. */
    uint64_t dial_failed;
    /* Attempts spent on a second, third, fourth or fifth dial of one session. Every failure of an
     * attempt earns one now, a refused handshake and a stranger's answer included; a hang does not,
     * because a handshake has no clock to fail on. */
    uint64_t dial_retried;
    /* Destinations the node accepted a request for and then refused.
     *
     * A diagnostic and nothing more. It used to feed a rule that replaced the whole QUIC connection
     * once three different destinations had been refused inside a window; that rule was this tree's
     * invention and is gone, because upstream reads the same event the other way — a refusal comes
     * back from ReadTCPResponse with `ok == false` and becomes coreErrs.DialError
     * (vendor/hysteria/core/client/client.go:221-224), which is an ordinary failed dial and never
     * touches the connection. Only wrapIfConnectionClosed produces the ClosedError that discards a
     * client, and it is reached from QUIC-level failures alone (:196, :202, :219). The equivalent
     * here is lc_qconn_step returning "ended", which already drops and rebuilds. */
    uint64_t stalled;

    /* Datagrams the connection would not take, and so were dropped.
     *
     * Dropping is what UDP is and is not by itself a fault. Saying so once per packet IS one: a
     * browser speaking HTTP/3 through a queue of sixteen produced eight identical `daemon.err`
     * lines inside one second on a box whose syslog is a ring buffer, which pushes out the lines
     * somebody would need to understand why. So the line is said once and the number is carried
     * here — and carried at all because nothing anywhere could answer whether sixteen is enough,
     * which is the only question worth asking about that queue. */
    uint64_t udp_dropped;

    /* How many times the source port moved. Kept because hopping is off by default and on only
     * where a node offers a range, so the one question worth asking about it — whether a silence
     * follows a hop — needs both this and the timestamps of the lines around it. */
    uint64_t hops;

    /* Datagrams that could not be ROUTED at all, as opposed to dropped under pressure. A queue that
     * is full is the reference's own shape — DiscardOverflow — and says the path is working and
     * busy. No address slot, no reply socket, a length nothing can carry: those say the path could
     * not be built for this datagram, which is a different question with a different answer, and
     * counting them together hid both. */
    uint64_t udp_unroutable;

    /* THE POOL, IN THE WAYS A POOLED CONNECTION CAN END.
     *
     * Every one dialled ends in exactly one of three, and test/seam holds the identity: `taken` — a
     * request got it, whatever became of the request; `expired` — a request reached it after its two
     * minutes and closed it, the way the reference's taker does; `failed` — it never finished its dial.
     * The three did not always add up: a spare that died BEFORE becoming available once fell through
     * every counter there was, and the line printed "3 dialled, 0 used" and nothing else.
     *
     * `lost` is not an ending and is not in the sum. It is the node closing a connection that is still
     * waiting to be taken — which the reference does not notice either, so that connection stays in
     * the pool and is taken or expires like any other. The number is here because it says how often a
     * request is about to be written onto a connection the node has already given up on. */
    uint64_t spare_dialled, spare_taken, spare_expired, spare_lost, spare_failed;
} stats;

/* THE REFERENCE'S GARBAGE COLLECTOR, AS FAR AS IT CLOSES SOCKETS — a model (DIVERGES: G3).
 *
 * When a REALITY handshake fails, Xray returns the error and does not close the connection
 * (`if err := uConn.HandshakeContext(ctx); err != nil { return nil, err }`,
 * vendor/Xray-core/transport/internet/reality/reality.go:201-203, and the dialer returns it too,
 * vendor/Xray-core/transport/internet/tcp/dialer.go:96-98): the socket stays open until the
 * collector finds the netFD unreachable and its finalizer closes it. Until then the node sees no
 * FIN from the client, and data it sends lies unread, so the close is a RST when it comes.
 *
 * When the collector runs is Go's runtime and nobody's code, so it is modelled from what it did,
 * measured with gctrace on Xray-core v26.9.9 as a client (tools/vendorcap/gcstand, 2026-10-01):
 * the live heap about 1 MB and the goal Go's floor of 4 MB, so a cycle every 3 MB of allocation;
 * about 210 KB allocated per REALITY handshake, succeeded or failed (195 connections, 14 cycles;
 * failed attempts 150–250 KB); one byte per 56 carried through the process (31 GB, 186 cycles; a
 * spliced download allocates nothing); and with nothing allocated, the runtime's forced cycle every
 * 120 s (forcegcperiod). Parked sockets are closed at the next cycle; the clock runs whether any
 * are parked or not, as the collector's does. */
#define GCEMU_BUDGET    (3u * 1024u * 1024u)
#define GCEMU_HANDSHAKE (210u * 1024u)
#define GCEMU_PER_BYTE  56u
#define GCEMU_FORCED_MS 120000u

static struct {
    uint64_t alloc, bytes_seen, last_ms;
    int     *fds;
    size_t   n, cap;
} gcemu;

/* What the reference would have carried through its buffers: everything but the spliced download. */
static uint64_t gcemu_bytes(void)
{
    return stats.bytes_in + stats.bytes_out + stats.udp_bytes_up + stats.udp_bytes_down +
           stats.copied_bytes + stats.direct_up_bytes;
}

static void gcemu_cycle(uint64_t now)
{
    for (size_t i = 0; i < gcemu.n; i++)
        close(gcemu.fds[i]);
    gcemu.n = 0;
    gcemu.alloc = 0;
    gcemu.last_ms = now;
}

/* Counted up to now; a cycle if the budget is spent or the forced period has passed. */
static void gcemu_tick(uint64_t now)
{
    if (gcemu.last_ms == 0u) {
        gcemu.last_ms = now;
        gcemu.bytes_seen = gcemu_bytes();
    }
    uint64_t b = gcemu_bytes();
    gcemu.alloc += (b - gcemu.bytes_seen) / GCEMU_PER_BYTE;
    gcemu.bytes_seen = b;
    if (gcemu.alloc >= GCEMU_BUDGET || now - gcemu.last_ms >= GCEMU_FORCED_MS)
        gcemu_cycle(now);
}

static void gcemu_handshake(void)
{
    gcemu.alloc += GCEMU_HANDSHAKE;
}

/* A failed attempt's socket, left to the collector. A descriptor that cannot be kept is closed now,
 * which is the old behaviour and no worse. */
static void gcemu_park(int fd)
{
    if (gcemu.n == gcemu.cap) {
        size_t cap = gcemu.cap ? gcemu.cap * 2u : 16u;
        int   *v = realloc(gcemu.fds, cap * sizeof *v);
        if (v == NULL) {
            close(fd);
            return;
        }
        gcemu.fds = v;
        gcemu.cap = cap;
    }
    gcemu.fds[gcemu.n++] = fd;
    gcemu_tick(lc_now_ms()); /* the handshake just counted may itself be what fills the heap */
}

/* How long the loop may sleep before the forced cycle is due, when there is something to close. */
static int gcemu_wait(int cap)
{
    if (gcemu.n == 0u)
        return cap;
    uint64_t now = lc_now_ms(), at = gcemu.last_ms + GCEMU_FORCED_MS;
    int      in = at > now ? (int)(at - now) : 0;
    return in < cap ? in : cap;
}

/* Which plane this run carries, for the summary alone:  itself is declared further down, and
 * the summary has to know because half its counters belong to one plane and read as a contradiction
 * on the other. Set once, in main, beside hy.on. */
static int on_hy_plane;

/* Whether the drop above has already been described since the last summary. */
static int udp_drop_said;

static volatile sig_atomic_t want_stats;

/* Only a flag is set here: everything else a summary needs is done on the next turn of the loop,
 * where it is allowed to allocate, print and take its time. */
static void on_usr1(int sig)
{
    (void)sig;
    want_stats = 1;
}

/* And zeroed on request, so a measurement can be taken on a tunnel that is carrying other people's
 * traffic at the same time.
 *
 * A separate instance was tried first and is cleaner in principle: it needs a target that answers
 * over plain HTTP without redirecting to TLS, and every candidate either redirected or was refused
 * from the node's country. Resetting the counters on the live one measures the path that actually
 * works, which is the one worth profiling. */
static volatile sig_atomic_t want_reset;

static void on_usr2(int sig)
{
    (void)sig;
    want_reset = 1;
}

/* A one-directional byte queue. Written from the front, drained from the back, compacted only when
 * it has to be — a memmove per event would cost more than the copy it saves. */
typedef struct {
    uint8_t *buf; /* storage lives in the session, because the two queues are not the same size */
    size_t   cap;
    size_t   len; /* bytes held */
    size_t   off; /* bytes already handed to the kernel */
} queue;

static size_t q_pending(const queue *q)
{
    return q->len - q->off;
}

static size_t q_room(queue *q)
{
    if (q->off > 0 && q->off == q->len)
        q->len = q->off = 0;
    return q->cap - q->len;
}

static int q_push(queue *q, const uint8_t *data, size_t len)
{
    if (len > q_room(q)) {
        /* Compaction is the last resort before refusing, not the routine path. */
        if (q->off > 0) {
            stats.compactions++;
            memmove(q->buf, q->buf + q->off, q->len - q->off);
            q->len -= q->off;
            q->off = 0;
        }
        if (len > q->cap - q->len)
            return -1;
    }
    memcpy(q->buf + q->len, data, len);
    q->len += len;
    return 0;
}

/* Hands as much as the kernel will take. Returns 0 when the queue is merely not empty yet, and -1
 * only for an error that ends the connection — a short write is the normal case, not a failure. */
static int q_flush(queue *q, int fd)
{
    while (q->off < q->len) {
        ssize_t n = write(fd, q->buf + q->off, q->len - q->off);
        if (n > 0) {
            q->off += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;
        if (n < 0 && errno == EINTR)
            continue;
        return -1;
    }
    q->len = q->off = 0;
    return 0;
}

/* Room to open one record and seal one frame, shared by every connection.
 *
 * Shared, and the reason it is safe to share is narrow enough to be worth stating precisely: nothing
 * here outlives the call that uses it. One thread, one event handler at a time, and no handler ever
 * suspends holding any of it. That is exactly NOT true of the handshake, where the same trick was
 * once used and two connections shaking hands at the same time quietly wrote over each other — the
 * buffers there span waits for the peer, so they belong to the connection and are allocated with it.
 *
 * The difference is worth fifty-eight kilobytes per connection. On the session it made one cost
 * 112 KB and the process 28.6 MB at the connection limit, against 35 MB free on the target device —
 * a device anyone on the LAN could then exhaust by opening connections. Here it costs 58 KB once. */
static struct {
    uint8_t plain[LC_REC_MAX_WIRE12];       /* a record, opened — all the header let through */
    uint8_t unpadded[LC_REC_MAX_PLAINTEXT]; /* the same, with Vision's framing removed */
    uint8_t framed[READ_CHUNK + 1024u];     /* what the client said, framed */
    uint8_t rec[MAX_REC];                   /* the same, sealed */
} scratch;

/* The threads that open the node's records ahead, one pool per process — started in the worker the
 * first time a read leaves more than one record in hand, since threads do not survive the fork that
 * makes workers. NULL on a single processor and until then. See tls/recopen.h. DIVERGES: O3. */
static lc_recopen *recopen;
static int         recopen_tried;

/* What the loop hands back. It reports events by attached pointer and deliberately not by
 * descriptor, so each side of a session registers its own tag: the alternative is a handler that
 * has to guess which half woke it, and guessing produced a version that read the client whenever
 * the node spoke. */
struct session;
typedef struct {
    struct session *s;
    int             is_lan; /* 0 node, 1 LAN, 2 spider worker wake */
} endpoint;

/* One proxied connection. Both descriptors and every buffer live here and die together: the single
 * hardest bug in a proxy is a buffer that outlives the connection it belonged to, and the only
 * reliable defence is that there is exactly one owner.
 *
 * Allocated per connection rather than taken from a static table. The table cost 8.6 MB of BSS on a
 * device with 35 MB free, all of it resident whether one connection was open or none. */
/* A connection's life in three parts. Everything before OPEN happens inside the event loop rather
 * than inside the accept handler, which is the whole point: the round trip to the node plus the key
 * exchange used to be spent with every other connection on the device waiting. */
typedef enum {
    ST_CONNECTING, /* TCP is on its way to the node */
    /* Between two attempts at the same dial, holding nothing but the client's socket and a clock.
     * The reference spends this interval in time.Sleep inside its own goroutine; a single-threaded
     * client spends it as a state, which is the same wait without the thread. See DIAL_TRIES. */
    ST_REDIAL,
    ST_HANDSHAKE, /* TLS 1.3 and REALITY, driven by lc_client_hs */
    ST_OPEN,      /* carrying traffic */
    /* The node answered, and answered as somebody else. What happens then is not a teardown: see
     * reality/spider.h. The session stays up long enough to fetch the site it was pretending to be,
     * carries nothing for the client, and ends on the server's END_STREAM or on the deadline. */
    ST_SPIDER,
    /* Shaken hands with the node and waiting for somebody to want it. Everything an open tunnel has
     * except a destination — which is the point, because nothing above this line depends on where
     * the traffic is going. See the `spare` block for what it costs and what it buys. */
    ST_SPARE,
    /* A request with the pool on and nothing in it yet: the client is here, its destination is
     * known, and it waits for the next pooled connection to finish its dial — the reference's
     * `<-h.preConns` (vendor/Xray-core/proxy/vless/outbound/outbound.go:177). No socket towards the
     * node of its own, ever: with the pool on, a request is served from it or not at all. */
    ST_POOLWAIT,
    /* A request on the Hysteria2 plane with no connection to ride: it waits for the one being made,
     * the reference's reconnectableClientImpl holding its mutex (vendor/hysteria/core/client/
     * reconnect.go:69-88). No descriptor of its own on the loop until it is served. See hy_start. */
    ST_HYWAIT,
} sess_state;

/* One address a datagram session is talking to, and the socket that answers as that address.
 *
 * The host is kept as text because that is what goes into the frame — lc_xudp_wrap takes a name or
 * a literal and spells whichever it was, exactly as the reference does. For an intercepted datagram
 * it is always a literal; the configured form (`-u PORT@HOST:PORT`) is where a name can appear.
 *
 * ⚠️ THE TABLE HAS NO CEILING, as the reference's has none. There were thirty-two on the REALITY
 * plane, and a thirty-third address retired the quietest — closing its reply socket, so that its
 * next answer was dropped as coming from nowhere. Xray's writer keeps a socket for every address
 * that answers in a map, and closes them only when the session ends
 * (vendor/Xray-core/proxy/dokodemo/dokodemo.go:215-273). A session is ended by its timer, so what
 * bounds the table is how many addresses a client talks to within one idle timeout — a torrent
 * client's peers, a game's — and the descriptors, raised the way Go raises them (see main). On the
 * Hysteria2 plane a session is one (src, dst) pair and the table holds that one entry. */
struct udp_dest {
    char     host[256];
    uint16_t port;
    int      reply_fd;
};

/* Sixteen kilobytes, which is the size of the uplink the reference gives a UDP inbound:
 * `pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(16*1024))`
 * (vendor/Xray-core/app/proxyman/inbound/worker.go:289). */
#define UDP_PEND_BYTES 16384u

/* The reference's BufferedWriter: one buffer of buf.Size, handed on each time it fills. See bufw_write. */
typedef struct {
    uint8_t buf[READ_CHUNK]; /* buf.Size */
    size_t  len;
} bufw;

/* ⚠️ BOUNDED BY BYTES AND ORDERED BY ARRIVAL, which is what the reference's pipe is — and what this
 * was NOT until a measurement showed the cost. It held four slots and, within one destination, let
 * the newest replace the one waiting. That rule was correct while a session WAS a destination: a
 * resolver that asks twice wants the second answer. Applied to a STREAM of datagrams to one address
 * it destroys them.
 *
 * Measured on the stand: four hundred datagrams sent in thirty milliseconds, while the session
 * spent seventy-seven opening, arrived as ONE. Not dropped — collapsed, and `dropped going up`
 * stayed at zero because nothing here counted it. Spanning destinations it was worse than lossy: on
 * three queries from one socket, twenty-nine bytes went upstream and one answer came back, because
 * the survivor of a collision went out under the FIRST destination's address. The replace rule is
 * unchanged WITHIN a destination — a resolver that asks twice wants the second answer — and what it
 * must never do is span them.
 *
 * ⚠️ AND THE REFERENCE'S OWN NUMBER IS NO LONGER A DEDUCTION. Xray 26.7.28 built from
 * an Xray build, run as a client on a workstation with a dokodemo-door UDP inbound and a
 * vless+reality+vision outbound, given the same four-hundred-datagram burst, returned 41 of 400 at
 * 400 bytes, 21 at 800, and 14 at 1200 — tracking `16384 / size` at every size, with the VOLUME
 * returned pinned near 16 KB regardless. The +1 is the datagram already off the pipe while the rest
 * queue. Controls: 393 of 400 direct without the tunnel, and 332 of 400 when the same burst is
 * paced 5 ms apart, so it is a queue and not a ceiling. A full queue dropping what does not fit is
 * therefore the shape to match, not a shortcoming to engineer around — see
 * tools/vendorcap/README.md for the recipe.
 *
 * A flat buffer rather than slots, because the bound is a size and not a count. Sixteen kilobytes of
 * fifty-byte lookups is three hundred of them; of full-sized datagrams it is four. Fixed slots would
 * have to be sized for the largest and would then cost a megabyte a session to hold the smallest.
 *
 * Each entry: one byte of host length, the host, the port, the payload length, the payload. The
 * destination travels WITH the datagram rather than as an index into the address table, because the
 * table retires entries and an index into it stops meaning what it meant. */
struct udp_pend {
    size_t   len;   /* bytes used of buf */
    unsigned count; /* datagrams held, for the drop accounting */
    uint8_t  buf[2u * UDP_PEND_BYTES]; /* the write under way, and the pipe behind it */
    /* The request's buffered write, kept here rather than shared because on this path it can stop
     * part way — the first write takes every datagram that arrived during the handshake, which can
     * be more than the queue towards the node holds at once. */
    bufw     request;
};

/* One VisionWriter.WriteMultiBuffer in progress: what it decided before framing anything, and how far
 * through its buffers it is. Kept on the session because a write can stop between two buffers for
 * want of queue room and carry on when the socket drains; see the functions that fill it. */
typedef struct {
    size_t   pieces;       /* buffers after ReshapeMultiBuffer — the loop's len(mb) */
    size_t   piece;        /* and the loop's i */
    int      raw;          /* the writer had been switched to the socket before this call */
    int      framing;      /* `*isPadding` as the call began */
    int      filtering;    /* the filter's gate was open, and it has not concluded */
    int      complete;     /* IsCompleteRecord over every buffer */
    int      long_padding; /* the loop's running longPadding */
    int      stop;         /* the loop's `break` has happened */
    int      cr_bad;       /* IsCompleteRecord, streamed: already false */
    unsigned cr_head;      /* header bytes it still expects, 5 down to 0 */
    size_t   cr_left;      /* record bytes it still expects */
} vision_mb;

typedef struct session {
    endpoint lan_tag;
    endpoint up_tag;

    /* Datagrams instead of a stream. The differences are small but they are everywhere: there is no
     * accepted socket to own, the client is an address on a shared socket rather than a connection,
     * every payload keeps its own boundary, and nothing ever half-closes — a resolver that has said
     * everything simply stops speaking, and the only way to know it is finished is that it has been
     * quiet for a while. */
    int                     is_udp;
    /* A datagram session carried as command 0x02 rather than xudp: no Vision flow and a first
     * datagram for port 53 or 443 — see lc_vless_request_udp_plain. Decided once, by the datagram that
     * made the session, as the reference's Dispatch decides it by the first packet's destination. */
    int                     plain_udp;
    /* Its datagrams carry no address of their own: the listener is not transparent, the one
     * destination is the configured one — see lc_xudp_wrap_unaddressed. */
    int                     udp_unaddressed;
    /* The packet a 0x02 stream is delivering: the length its header declared, what of it has
     * arrived, and where it is kept until it is whole — see plain_datagrams. */
    size_t                  plain_need, plain_got;
    uint8_t                *plain_pkt;
    /* How much of that packet has gone: one longer than buf.Size goes as several datagrams, and the
     * client's socket may fill between two of them. */
    size_t                  plain_at;
    /* A reply the client's socket would not take yet, and a duplicate of that socket the loop
     * watches for room: -1 while nothing waits. The reference's writer waits inside WriteTo, and
     * nothing behind it moves meanwhile — see reply_wait. */
    int                     reply_wait_fd;
    /* The reply being written has been accounted — the timer, the byte count — so a second attempt
     * at it does not count it twice. */
    int                     reply_counted;
    /* The Hysteria2 plane's packet the socket would not take, kept until it does. */
    uint8_t                *reply_held;
    size_t                  reply_held_len;
    /* Whether the first xudp frame has gone. It carries status New; every one after it carries
     * Keep. A per-session bit and not a per-destination one, which is the reference's shape: New
     * opens the session, and each frame after it names its own address (xudp.go:117-121). */
    int                     xudp_started;
    struct sockaddr_storage peer;
    socklen_t               peer_len;

    /* THE DESTINATIONS THIS ONE SESSION CARRIES.
     *
     * A datagram session belongs to the CLIENT, not to the address it is talking to. That is the
     * reference's model and the reason its frames state an address at all: one xudp stream serves
     * everything one source sends, and the node keeps one NAT mapping for it — which is what
     * full-cone means and what a stream per destination cannot have, since a shared global id would
     * make each new destination detach the one before it
     * (vendor/Xray-core/common/mux/server.go:195-227).
     *
     * Allocated only for UDP sessions. A TCP session would carry the table unused, and this
     * structure is already the largest thing this program allocates per connection.
     *
     * The reply socket is per DESTINATION and has to be: a transparent reply must come from the
     * address the client thought it was talking to, so one socket cannot answer for two of them. */
    struct udp_dest        *dests;
    unsigned                dest_cap;
    unsigned                dest_count;

    /* This client, as the node knows it. See client_global_id. */
    uint8_t                 global_id[8];

    /* What the client said while the tunnel was still being built. Dropping it instead would work —
     * a resolver retries after a second — but that second is the whole latency of the first name a
     * device looks up after it wakes.
     *
     * A queue and not a slot, and allocated with the destination table because only a datagram
     * session has one: see struct udp_pend for why one slot stopped being enough the moment a
     * session began carrying more than one address. */
    struct udp_pend *pend_q;

    int        lan_fd;
    int        up_fd;
    /* A failed handshake: its socket goes to the model of the collector, not to close() — see gcemu. */
    uint8_t    gc_park;
    /* A dial to a node given by name, while it is in the air: `up_fd` is then its descriptor and not
     * a connection — see dial_turn. NULL for a node given as an address, whose dial is up_fd itself. */
    lc_dial   *dial;
    sess_state st;
    uint64_t   deadline;

    /* When a quiet datagram session gives up. A stream ends when someone closes it; a datagram
     * session has nothing of the kind — the client cannot say it is finished and the resolver
     * simply stops answering — so silence is the only end there is, and without this one they live
     * for the life of the process, each holding a slot and a descriptor. */
    uint64_t idle_deadline;

    /* The REALITY plane's ActivityTimer — see CONNECTION_IDLE_MS: the timeout in force (zero until
     * the request starts it), when it is next checked, and whether anything moved since the last
     * check. And which of the two copies has ended, which is what moves it. */
    uint64_t act_ms;
    uint64_t act_next;
    int      act_seen;
    int      req_done, resp_done;

    /* A REALITY datagram session's lastActivityTime, in whole seconds: see UDP_CHECK_MS. */
    uint64_t udp_seen_s;

    /* And the stream equivalent, which is a different rule and now says so by being a different
     * field: a datagram session is bounded by silence from the moment it last spoke, a stream only
     * once its client has finished asking. They shared one uint64_t and the two rules read it
     * differently on alternate lines. */

    /* When this session started asking, kept so that the answer to "how long did the person wait"
     * can be given in milliseconds instead of inferred.
     *
     * It exists because counting refusals turned out to measure the wrong thing. Shortening the
     * handshake budget from fifteen seconds to three MUST produce more of them — a shorter budget
     * cuts earlier by construction — so the two settings cannot be compared by how often the client
     * gave up. Comparing them anyway is exactly the mistake that was made here: 22% of refusals
     * over hours was laid beside 5% over one hour and called a twelvefold improvement, when the
     * like-for-like figure was 9 against 14 and pointed the other way.
     *
     * What a person actually experiences is the wait until the page starts loading, and a refusal
     * that is followed by a successful retry half a second later costs them less than one that
     * succeeds after fifteen. That is what this measures. */
    uint64_t began_ms;

    /* Which attempt at the node this is — 1 for the first — and, while ST_REDIAL, when the next one
     * may start. Both exist because the reference dials up to five times for one session; the rules
     * and the numbers are at DIAL_TRIES. */
    uint8_t  dial_try;
    uint64_t redial_at;

    lc_client     cl;
    lc_client_hs *hs;
    lc_vision     vision;
    int           use_vision;

    /* Dialled ahead of need and not yet claimed by anybody. Cleared the moment it is, so that from
     * `spare_bind` onwards this session is indistinguishable from one dialled for its own client —
     * which it has to be, because every path below this line is shared. */
    int           is_spare;
    /* A pooled connection the node has closed, or broken, while it waited. Kept in the pool rather
     * than dropped, because the reference does not look at a pooled connection until a request takes
     * it; its descriptor is off the loop until then. See spare_died. */
    int           spare_dead;
    /* Arrival order among requests waiting on the pool (ST_POOLWAIT), which is the order the
     * reference's channel serves its receivers in. */
    uint64_t      pool_seq;

    queue   to_up;  /* sealed records waiting for the node */
#if LC_HYSTERIA
    /* On the Hysteria2 plane this queue is filled by the reader thread rather than by this loop —
     * see net/reader.h, and CONCURRENCY.md for the measurement that asked for it. The stage holds
     * the lock that makes `to_up.len` and `to_up.off` safe to share; nothing else about the session
     * is shared with that thread. Unregistered (fd -1) on every other plane and for datagrams. */
    lc_reader_stage stage;
#endif
    queue   to_lan; /* plaintext waiting for the client */
    uint8_t to_up_buf[UP_QUEUE_SIZE];
    uint8_t to_lan_buf[LAN_QUEUE_SIZE];

    /* What has been read of the node's side and not yet taken: records, the one under assembly
     * first. The node's records arrive split across reads, and a client that assumes otherwise
     * works on a LAN and fails across the Baltic.
     *
     * Read as the reference reads it — `rin` is the shape of uTLS's rawInput, and every read of
     * the node's socket asks for what the reference's would (see tls/rawin.h and node_fill). `rx`
     * is `rx_small` until the reference's buffer outgrows it, and then as large as that from the
     * heap; `rx_len` is always `rin`'s length. Except on an open tunnel with threads to open
     * records ahead, which reads a bufferful and keeps `rin` in the shadow: there `rx_len` is
     * `rin`'s length and `rin_ahead` — see node_read_ahead. */
    uint8_t  rx_small[MAX_REC];
    uint8_t *rx;
    size_t   rx_cap;
    size_t   rx_len;
    lc_rawin rin;
    /* Of the record at the front of `rx`, how much the handshake machine has been given — see
     * hs_pump. */
    size_t hs_fed;
    /* On an open tunnel the socket is read ahead of the reference, a bufferful at a time, and `rin`
     * follows in the shadow: these are the bytes read that the reference would not have read yet.
     * They decide how the connection is closed — see node_read_ahead and session_close. DIVERGES: O3. */
    size_t rin_ahead;
    /* What the reference's Conn keeps about the node's side once the handshake is over — see
     * tls/post.h. */
    lc_post post;
    /* KeyUpdates the node asked to be answered whose answer has not yet found room in to_up — see
     * node_key_update. While there is one, nothing is read from the node. */
    unsigned ku_owed;

    /* Where this connection was headed, kept because the VLESS request naming it is only sent once
     * the tunnel is up, which is now several events after the client was accepted. The account it
     * goes out under is kept for the same reason; both are program constants, borrowed not copied. */
    char           target_host[256];
    uint16_t       target_port;
    const uint8_t *uuid;
    const char    *flow;
    /* The server name the handshake used, borrowed like the two above. Needed after the handshake
     * only on the path where it failed: the spider addresses its request to it. */
    const char    *sni;

    int vless_header_seen;
    /* What of the response header has arrived — see lc_vless_response_feed. */
    lc_vless_resp vresp;

    /* Set once the node has announced that everything it sends from here on is raw. From that point
     * the outer TLS is over for this direction: the bytes on the socket are the inner connection's
     * own TLS records, already encrypted end to end by whoever opened them, and unwrapping them a
     * second time is the cost Vision exists to remove — 278 Mbit/s against 642 on the measured
     * hardware.
     *
     * The node decides this on its own and only when it has satisfied itself that the inner stream
     * is TLS 1.3, so nothing is ever passed through unencrypted by this shortcut. */
    int direct_in;
    /* Writer suppression begins on the write AFTER its Direct announcement,
     * matching VisionWriter.WriteMultiBuffer, not when direct_out is set. */
    int raw_writer;

    /* The kernel pipe that carries the raw stream once direct copy is on. splice moves pages between
     * the two sockets through it without the bytes ever entering this process: 519 Mbit/s against
     * 278 for the same stream copied through a buffer here.
     *
     * Created only when direct copy actually engages, and sized as Go sizes its splice pipe, to
     * maxSpliceSize — see SPLICE_MAX and splice_direct. It was sized DOWN to 16 KB until
     * 2026-09-24, for memory, and that made this client read the node differently from the reference.
     * The size is a ceiling, not an allocation: the pipe holds pages only while a drain is in it,
     * and a drain is written out before the next one is taken.
     *
     * in_pipe is what the last drain put there and the pump has not yet written: nonzero means the
     * node is not being read. */
    int    pipe_rd, pipe_wr;
    size_t in_pipe;

    /* Each direction ends on its own. A connection where one side has finished speaking is normal —
     * an HTTP request is exactly that — and tearing the whole thing down on the first EOF truncates
     * the reply. */
    int closing;           /* no more application I/O; reap follows the final close */
    uint64_t close_by;     /* pending close_notify write deadline; zero after teardown */
    int own_fail;          /* ended by a failure of this client's own: no close_notify — see own_failure */
    int lan_eof, up_eof;   /* that side sent us EOF */
    int raw_poll_paused;   /* no node Read until the preceding Vision write completes */
    int lan_on_loop;       /* the client's descriptor is registered — from the moment the tunnel opens */
    /* Whether one byte has ever come back for this session. Not the same question as "is it open":
     * a stalled tunnel opens streams normally and answers none of them. */
    int got;

    /* On the Hysteria2 plane, this connection's stream on the one shared QUIC connection. Zero when
     * this session belongs to the REALITY plane, which is why handles from lc_qconn start at one.
     *
     * A session here owns no socket towards the node at all: up_fd stays -1, there is no TLS state,
     * no Vision and no splice pipe. What it keeps using are the two queues, because backpressure in
     * both directions is the same problem whichever plane carries the bytes. */
    int hy_h;

    /* A datagram pair's first packet has gone to the node. The reference sends that one whatever its
     * length and every later one only `if n > 0` — see hy_send_datagram. */
    int hy_first_sent;

    /* Bytes of that stream already read — credited to the node — and not yet in to_lan: what is
     * left of the reference's last Read of up to 32 KiB, which io.Copy writes out whole before it
     * reads again. See hy_pump. */
    size_t hy_read;

    /* Which connection that handle belongs to. See hy.gen: a handle is only meaningful to the
     * connection that issued it, and connections are remade. */
    uint64_t hy_gen;


    /* What Go's tls.Conn tracks to size its records: `packetsSent`, the application-data records
     * cut while below the boost, and `bytesSent`, every byte the socket took — handshake included.
     * See tls_write. */
    uint64_t tls_records_sent;
    uint64_t tls_bytes_sent;

    /* The VLESS request is not written yet, and when it stops waiting for the client's first bytes.
     * Only ever set on the REALITY plane, between the handshake and request_write. */
    int      request_due;
    uint64_t request_by;

    /* The MultiBuffer being written towards the node, when a write has more than one buffer and may
     * stop between two of them: how many it has, how many have gone, and where the rest is — in
     * pend_q from `up_at` on a datagram session, still in the kernel's receive queue (`up_left` bytes)
     * on a stream. See udp_pump and stream_pump. */
    unsigned  up_n, up_done;
    size_t    up_at, up_end;
    size_t    up_left;
    vision_mb up_mb;

    /* What the reference's spider does on a connection whose node answered as a stranger: its
     * HTTP/2 client and the http.Client around it — the request, every frame the site sends, the
     * redirects it follows, the window it hands back, the harvest of the page (reality/fetch.c).
     * Only ever set in ST_SPIDER, and freed with the session. */
    lc_spider_fetch *fetch;
    /* x/net has closed the connection: the writes it made before are still to go, and then the close
     * tls.Conn.Close makes — close_notify behind them, as every Write before it had returned. */
    int spider_end;
    pthread_t spider_worker;
    int       spider_worker_on;
    pthread_t spider_request_worker;
    int       spider_request_worker_on;
    int       spider_wake_fd;
    int       spider_write_pending;
    uint8_t  *spider_write;
    size_t    spider_write_len, spider_write_off;
    int       spider_ku_pending; /* KeyUpdate reply sealed, not yet fully written to socket. */
    int       spider_peer_lost;
    _Atomic int spider_worker_result;
    _Atomic int spider_request_result;
    _Atomic int spider_worker_done;
    _Atomic int spider_request_done;
    endpoint  spider_tag;
#if LC_SPIDER_PROFILE
    /* Diagnostic build only. Worker publishes immutable samples; the loop alone logs,
     * after the first request reaches the socket. No extra wake, deadline or driver. */
    uint64_t spider_profile_base, spider_profile_handoff, spider_profile_fetch, spider_profile_create;
    uint64_t spider_profile_logged, spider_profile_allocated, spider_profile_transferred;
    uint64_t spider_profile_created, spider_profile_wake, spider_profile_opening;
    /* Each task writes its immutable timestamp before publishing a native-width
     * ready flag. Atomic uint64_t would require libatomic on MIPS32. */
    uint64_t spider_profile_entry, spider_profile_request_entry;
    _Atomic unsigned spider_profile_entry_ready, spider_profile_request_entry_ready;
    _Atomic unsigned spider_profile_count;
    struct {
        uint64_t wait_begin, wait_end, step_begin, step_end;
        int result;
    } spider_profile_steps[16];
    unsigned spider_profile_writes;
    int spider_profile_headers, spider_profile_reported;
#endif

    /* The reference reader's allocStrategy.current: how many buffers its next readv offers, 1 to 8.
     * Zero reads as one. See stream_take. */
    unsigned rv_alloc;
} session;

/* What one splice from the node may move, and what the pipe is sized to hold: Go's maxSpliceSize,
 * "1MB is the default maximum pipe buffer size, which is determined by /proc/sys/fs/pipe-max-size"
 * (GOROOT/src/internal/poll/splice_linux.go:21-25). See splice_direct. */
#define SPLICE_MAX (1 << 20)

/* Every line of this log carries the time it happened.
 *
 * Without it the log says what occurred and never when, and that is the difference between a report
 * and a diagnosis: the failures found on the device clustered at 6.2 and 15.4 seconds, and matching
 * those to anything here meant counting lines and guessing. Seconds and milliseconds off the same
 * monotonic clock the timeouts use, so a "giving up" can be laid beside the client's stopwatch
 * without arithmetic.
 *
 * Monotonic rather than wall clock: a router's clock jumps when NTP first answers, which on a fresh
 * boot is exactly while the first connections are being made.
 *
 * AND IT DOES NOT WRAP, which it used to. The seconds were printed as `t / 1000u % 10000u`, so after
 * ten thousand seconds — two hours forty-six minutes, less than one evening of uptime — the count
 * returned to zero and started again. Every reading then described two moments, and the one thing
 * this stamp exists to answer, "when did that happen", stopped having an answer. Seen for real while
 * reading a router's log: [9991.960] followed by [249.606] four minutes later, which reads exactly
 * like a process that restarted and was not one — the cumulative counters beside it had not moved.
 * A width of four digits is what suggested the modulo; the width is a minimum, not a maximum, so
 * printf widens the field on its own and days of uptime print correctly. */
/* Which worker this is, for the summaries alone. One process leaves both at their defaults and the
 * output is unchanged to the character; more than one, and every counted line says whose it is.
 *
 * ⚠️ THE PID DOES NOT ANSWER THIS, WHICH IS WHY THE FIELD EXISTS. It looked as though it would:
 * syslog prefixes each line with `lc-tunnel[PID]`, and the workers have different pids. But procd
 * captures the stdout of the instance it started and writes ALL of it under the parent's pid, so a
 * router running four workers logs four interleaved sets of counters, every one of them labelled
 * with the supervisor. Read on a live router after deploying exactly that. */
static unsigned worker_no;
static unsigned worker_total = 1;

/* ⚠️ EVERY LINE THIS PROGRAM SAYS ABOUT ITSELF GOES THROUGH HERE, and ten of them did not.
 *
 * `printf` is reserved for output a SCRIPT reads — `--planes` and `--version`, both one line and
 * both parsed by the installer. Everything else is a log line and belongs to note(), which stamps
 * the time and, once there is more than one worker, which worker is speaking.
 *
 * ⚠️ AND WHEN THAT WAS WRITTEN IT WAS STILL FALSE, because it was checked against `printf` alone:
 * twenty-five more runtime lines were leaving through `fprintf(stderr, ...)` — every Hysteria2
 * diagnostic a worker can produce, the one that says a connection was refused for want of a
 * descriptor, and everything said after the workers fork. Same defect, other function name. They are
 * note() calls now, and stderr is left to what is said before any worker exists and to what the
 * supervisor says, since it is then the only writer. A rule checked with one grep is a rule about
 * that grep; `make check-quiet-lib` is what checks this one now.
 *
 * The ten that escaped were the ones that mattered most for reading an incident: the two `direct
 * copy engaged` lines, the Hysteria node summary, and the startup banner. With four workers the
 * banner printed four identical times with nothing to tell the copies apart, and a per-connection
 * event carried neither a timestamp nor a worker — in a log where every neighbouring line had both.
 * Syslog does not help: it stamps the ident with the pid captured at openlog, which is the
 * supervisor's, so every worker appears as the same process.
 *
 * note() appends the newline itself. A format ending in \n here produces a blank line, which is how
 * this file will tell you the rule was forgotten again.
 *
 * ⚠️ AND IT GOES OUT IN ONE write(), which is lc_vsay's doing and not this function's. Four workers
 * share one pipe — procd gives the instance a single stdout and hands the same descriptor to every
 * fork of it, and `/proc/<each worker>/fd/1` on a live router is one inode — so a line delivered in
 * pieces comes back interleaved with theirs. This used to be three stdio calls, and what that cost
 * is written up in core/say.h together with the four experiments that pinned it down. */
static void note(const char *fmt, ...)
{
    /* Wide enough for the longest stamp uint64 milliseconds can make: four for "[w9 ", twenty
     * digits, a point, three more, and "] ". */
    char     stamp[40];
    uint64_t t = lc_now_ms();

    if (worker_total > 1u)
        (void)snprintf(stamp, sizeof stamp, "[w%u %4llu.%03llu] ", worker_no + 1u,
                       (unsigned long long)(t / 1000u), (unsigned long long)(t % 1000u));
    else
        (void)snprintf(stamp, sizeof stamp, "[%4llu.%03llu] ", (unsigned long long)(t / 1000u),
                       (unsigned long long)(t % 1000u));

    /* The stamp goes as a PREFIX rather than as part of the format, so that a caller's `%` can
     * never be read against it and a format taken from elsewhere cannot reinterpret it. */
    va_list ap;
    va_start(ap, fmt);
    lc_vsay(1, stamp, fmt, ap);
    va_end(ap);
}

/* A tunnel became usable: bucket how long its client waited for that.
 *
 * Only streams are counted. A datagram session is open the moment it exists — there is nothing to
 * wait for — so including them would dilute the buckets with instant zeroes and flatter whatever
 * budget is in force. */
static void note_open_wait(const session *s)
{
    if (s->began_ms == 0)
        return;
    uint64_t waited = lc_now_ms() - s->began_ms;
    if (waited > stats.open_worst_ms)
        stats.open_worst_ms = waited;
    if (waited < 250u)
        stats.open_under_250++;
    else if (waited < 1000u)
        stats.open_under_1s++;
    else if (waited < 3000u)
        stats.open_under_3s++;
    else if (waited < 5000u)
        stats.open_under_5s++;
    else if (waited < 10000u)
        stats.open_under_10s++;
    else
        stats.open_over_10s++;
}

/* "THIS ONE OPENED" — ONE FUNCTION FOR BOTH PLANES, and that is not tidiness.
 *
 * The line stood verbatim twice: in `hy_pump` (Hysteria2) and in the `main` loop (REALITY). On
 * 2026-08-19 the first was put behind a variable and the second was missed — so a change made for
 * the sake of the router's log did nothing for half the routers, and the measurement that showed what
 * it cost was taken on a Hysteria2 box and never saw the other path at all. The duplicate WAS the
 * mistake, so the duplicate is gone rather than a second switch added.
 *
 * ── WHY IT IS OFF AT ALL ──
 *
 * A router's log is a ring in RAM (`log_size` defaults to 128 KB on OpenWrt) and whatever does not
 * fit is gone for good. Measured on a live box: over 7 h 18 min the buffer held 1112 lines, 250 of
 * them this one — 22 % — while the two tunnel failures anyone goes to the log FOR took four lines.
 * The line did not cost "a little space", it cost depth: the window was seven hours instead of a
 * day and a half.
 *
 * ⚠️ AND IT IS A BROWSING HISTORY, not merely volume. A host and port per connection is a list of
 * where a person went, sitting in the system log for hours. Turn the variable on knowing that.
 *
 * What is lost while it is off: which addresses were opened, which is all the line ever said. How
 * many there were and how long they took to open is still counted by `note_open_wait` and printed
 * in the statistics block — the series that tells "it got worse" from "it was always like this".
 *
 * ── THE SHAPE OF THE SWITCH ──
 *
 * As with `LC_QUIC_LOG` (quic/conn.c): PRESENCE decides, the value is not parsed. So `LC_OPEN_LOG=0`
 * turns it ON too — a known trap, named here and in docs/DESIGN.md, and not worth changing the shape
 * for: disagreeing with the switch next door would cost more.
 *
 * Read ONCE: this is a hot path, and a getenv per connection would pay an environment search for an
 * answer that does not change over the life of the process. The laziness is safe: the loop thread is
 * the only one that asks — the Hysteria2 reader (net/reader.c) and the node lookups (net/dial.c)
 * are the other threads, and neither logs. */
/* ⚠️ A PREDICATE, NOT A LOCAL VARIABLE IN ONE FUNCTION — because the reasoning above is about a
 * CLASS of line, while what was written covered one, and the second line of the same class was left
 * without it.
 *
 * Taken from a live router 2026-08-27, five hours after the rollout: 1093 lines in the whole ring,
 * covering 1 h 39 min, 94 % of them ours, and 66 % of the ENTIRE SYSTEM LOG was one line —
 * `direct copy engaged` (729 of them). Three times worse than the "opened" line all of this was
 * written for.
 *
 * Both properties are the same ones. Depth: a window of an hour and a half instead of a day and a
 * half, and the tunnel failure anyone goes to the log for is evicted before they get to it.
 * History: the line carries `host:port`, which is a list of where a person went, in the system log.
 *
 * What is lost while it is off: which addresses got the hand-off to the kernel. How many there were
 * is counted by `pipes armed` and the spliced share in the summary, and that is what says whether
 * Vision is working at all. */
static int log_per_connection(void)
{
    static int on = -1;
    if (on < 0)
        on = getenv("LC_OPEN_LOG") != NULL;
    return on;
}

static void note_opened(const session *s)
{
    if (log_per_connection())
        note("opened %s:%u", s->target_host, s->target_port);
}

/* The summary, printed on the turn after SIGUSR1 asked for it — not from the handler, where
 * printing is not allowed and the numbers would be read while they were being written. */
static void report_stats(void)
{
    want_stats = 0;
    /* "chunks" rather than "records", because on the Hysteria2 plane they are not records: the two
     * counters are filled by hy_pump from stream reads and writes, and on the REALITY plane by the
     * record layer. Naming them after the REALITY meaning was the readable half of the same fault
     * that left them at zero here — an operator on the plane carrying all the traffic read a line
     * about records and got nothing that described what was happening. */
    note("chunks in %llu (%llu bytes, average %llu), out %llu (%llu bytes, average %llu)",
         (unsigned long long)stats.rec_in, (unsigned long long)stats.bytes_in,
         (unsigned long long)(stats.rec_in ? stats.bytes_in / stats.rec_in : 0),
         (unsigned long long)stats.rec_out, (unsigned long long)stats.bytes_out,
         (unsigned long long)(stats.rec_out ? stats.bytes_out / stats.rec_out : 0));
    /* AND THE ONES THAT CANNOT MOVE ON THIS PLANE ARE NOT PRINTED ON IT.
     *
     * The note above `chunks` describes a fault already fixed once: counters that belonged to the
     * REALITY plane printed zeroes on the Hysteria2 one while it carried a household, and an
     * operator read a line that described nothing. Three numbers on the next two lines were left in
     * exactly that state. `reads up` counts reads of the REALITY socket (there is one `read(s->up_fd`
     * in the file and it is on that path); on Hysteria2 the node's bytes arrive through ngtcp2 and
     * that counter is structurally zero. `vision frames` and everything about splicing is Vision,
     * which is REALITY only.
     *
     * Read live on a router carrying this very session: `reads up 0, lan 137` beside `chunks in 29
     * (34758 bytes)` — thirty-four kilobytes had arrived from the node and the line next to it said
     * no reads had happened. Both true, and together they read as a contradiction; the honest fix is
     * to print what the plane in use can actually report.
     *
     * `compactions` is on both, because both paths push into the queues (hy_pump among them).
     * `reads lan` was on both too, and on Hysteria2 it had joined the zeros this paragraph is
     * about: since the reader thread took the client's descriptor (net/reader.c) the loop reads
     * nothing from the LAN on that plane — an MT7621 router, 2026-09-23, `reads lan 0` beside
     * `chunks in 250 (280 311 bytes)`. It is printed where it can move. The datagrams dropped for
     * having no destination are counted by the one UDP listener both planes share, so they are
     * printed on both, below. */
    if (on_hy_plane) {
        note("compactions %llu", (unsigned long long)stats.compactions);
    } else {
        /* Both directions of "direct", and named by what each one costs rather than by one word for
         * two different things. Down is a splice and never enters this process; up is a copy into
         * the queue. Printing only the first is how twenty megabytes of upload came to be reported
         * as twenty kilobytes — see direct_up_bytes.
         *
         * ⚠️ AND THE SHARE IS WORKED OUT HERE RATHER THAN LEFT TO THE READER, because it is the one
         * number that says whether this tunnel is fast or slow and nothing else in the summary says
         * it. Measured 2026-08-27 on one box, same size, two peers: 99.93% spliced at 36.8 Mbit/s
         * against 0.23% at 17.6. Which of the two a connection gets is decided by the SERVER — it
         * announces the hand-off with CommandPaddingDirect, and the branch that sends it wants whole
         * TLS records end to end (vendor/Xray-core/proxy/proxy.go:366-379), which a response that
         * starts as a saturated stream never gives it. So a low share here is not a fault in this
         * client and not something a router can be configured out of; it is what the far end chose,
         * and the only reason to print it is that otherwise nobody can tell the two cases apart. */
        uint64_t got_down = stats.direct_bytes + stats.bytes_in;
        /* And how many of the node's records were opened ahead on the other cores, of those handed
         * to them — tls/recopen.h — on the same line, beside the reads they came from. */
        note("reads up %llu, lan %llu | vision frames %llu | compactions %llu"
             " | direct %llu bytes down (spliced, %llu%% of what came down), %llu up (copied)"
             " | %llu of %llu records opened ahead",
             (unsigned long long)stats.reads_up, (unsigned long long)stats.reads_lan,
             (unsigned long long)stats.vision_frames, (unsigned long long)stats.compactions,
             (unsigned long long)stats.direct_bytes,
             (unsigned long long)(got_down ? stats.direct_bytes * 100u / got_down : 0),
             (unsigned long long)stats.direct_up_bytes, (unsigned long long)stats.rec_ahead,
             (unsigned long long)stats.rec_handed);
        note("raw copied %llu bytes, pipes armed %llu, refused %llu",
             (unsigned long long)stats.copied_bytes, (unsigned long long)stats.pipes_armed,
             (unsigned long long)stats.pipes_failed);
        /* Printed unconditionally, including the zero: on the "-udp443" spelling zero is the answer
         * to "is the permission actually in effect", and a line that appears only when non-zero
         * cannot say that. */
        note("datagram sessions refused for UDP/443 by flow: %llu",
             (unsigned long long)stats.udp443_refused);
    }
    /* Same reasoning as the line above: zero is the answer to "is the listener recovering
     * destinations at all". On both planes, because the listener is shared. */
    note("intercepted datagrams dropped for having no destination: %llu",
         (unsigned long long)stats.udp_no_dst);

    /* The wait, and the refusals, on one line each and next to each other.
     *
     * Read the second without the first and a shorter budget looks like a regression every time:
     * it refuses more by construction. Read them together and the question becomes answerable —
     * refusals up while waits move to the left is the budget doing its job, and both moving right
     * is the budget cut too fine. */
    {
        uint64_t opened = stats.open_under_250 + stats.open_under_1s + stats.open_under_3s +
                          stats.open_under_5s + stats.open_under_10s + stats.open_over_10s;
        note("waits to open: <250ms %llu, <1s %llu, <3s %llu, <5s %llu, <10s %llu, 10s+ %llu"
             " (of %llu, worst %llu ms)",
             (unsigned long long)stats.open_under_250, (unsigned long long)stats.open_under_1s,
             (unsigned long long)stats.open_under_3s, (unsigned long long)stats.open_under_5s,
             (unsigned long long)stats.open_under_10s, (unsigned long long)stats.open_over_10s,
             (unsigned long long)opened, (unsigned long long)stats.open_worst_ms);
        /* THE CLOCKS NAMED HERE ARE THE ONES THAT APPLIED, and each plane's are its reference's — a
         * line that once printed one plane's budget while the other was running cost an hour of
         * reading the wrong fault into 839 give-ups.
         *
         * On the REALITY plane: a connect attempt that ran out of CONNECT_ATTEMPT_MS, and a request
         * that ran out of attempts — five dials, whatever each failed on. On the Hysteria2 plane: a
         * QUIC handshake abandoned by its clock, and a request that failed because the connection it
         * waited for could not be made. Neither plane has a clock on a handshake's answer beyond
         * those, or on a stream's. */
        if (on_hy_plane)
            note("gave up: %llu handshakes on the clock (%u ms idle, %u ms in all), %llu requests "
                 "with them; %llu dials failed outright",
                 (unsigned long long)stats.gave_up_connecting, LC_HY_HANDSHAKE_IDLE_MS,
                 LC_HY_HANDSHAKE_MS, (unsigned long long)stats.gave_up_handshake,
                 (unsigned long long)stats.dial_failed);
        else
            note("gave up: %llu while connecting (%u ms an attempt), %llu requests after %u attempts; "
                 "%llu dials failed outright, %llu retried",
                 (unsigned long long)stats.gave_up_connecting, CONNECT_ATTEMPT_MS,
                 (unsigned long long)stats.gave_up_handshake, DIAL_TRIES,
                 (unsigned long long)stats.dial_failed, (unsigned long long)stats.dial_retried);
#if LC_HYSTERIA
        /* No count of replacements beside it any more: this client no longer decides on its own
         * that the node's connection is useless. What ends one is QUIC saying so, which is the only
         * event the reference reconnects on. The two numbers that used to be printed at the moment
         * one was decided are still printed, at the moment one ENDS — see hy_turn.
         *
         * ⚠️ AND `on_hy_plane`, NOT ONLY `#if LC_HYSTERIA`. The two are not the same question: the
         * define asks what this binary was built with, the flag asks what it is doing right now.
         * The package that ships carries both planes, so on every REALITY router this printed a
         * counter with no path to a non-zero value — `stats.stalled` moves in two places and both
         * are on the QUIC session path. Found by listing every counter against its increment sites
         * rather than by reading the line, which is how the two before it were missed. */
        if (on_hy_plane)
            note("destinations the node refused: %llu", (unsigned long long)stats.stalled);
#endif
    }

    /* The pool, and on the plane that has one. The first four numbers add up — dialled is used plus
     * expired plus never opened, once nothing is still waiting in the pool — and test/seam asserts
     * it; the fifth is outside the sum on purpose. See the counters for what each one means. */
    if (!on_hy_plane)
        note("warm tunnels: %llu dialled, %llu used, %llu expired unused, %llu never opened; "
             "%llu closed by the node while waiting",
             (unsigned long long)stats.spare_dialled, (unsigned long long)stats.spare_taken,
             (unsigned long long)stats.spare_expired, (unsigned long long)stats.spare_failed,
             (unsigned long long)stats.spare_lost);

    /* The split a deployment decision hangs on, worked out here rather than left to whoever reads
     * the line: datagrams always pay this processor, streams stop paying it the moment Vision hands
     * them to the kernel. A tunnel whose traffic is mostly datagrams is a tunnel that will not go
     * faster for any reason except carrying fewer of them. */
    {
        /* Against EVERYTHING carried, not against the spliced bytes alone. Measured the narrow way,
         * a tunnel that moved twenty megabytes through the record layer and a kilobyte of DNS
         * reported a datagram share of 100 %, because streams that paid the processor were missing
         * from the denominator — the opposite of the reading the number exists to give. */
        uint64_t udp = stats.udp_bytes_up + stats.udp_bytes_down;
        /* ⚠️ AND direct_up_bytes BELONGS HERE, which is the half that was missing and the reason
         * this fix is not only about a line being short. The comment above says the denominator has
         * to be EVERYTHING carried or the share reads the opposite of what it means; the upstream
         * direct path carried more than any other and was in neither the numerator nor the
         * denominator, so the very fault described above was still live one term later. */
        uint64_t streamed = stats.direct_bytes + stats.direct_up_bytes + stats.copied_bytes +
                            stats.bytes_in + stats.bytes_out;
        uint64_t all = udp + streamed;
        /* Kept beside the pressure drops in the line below, and separate from them: "the queue was
         * full" is a busy path, "this could not be routed" is a broken one. */
        note("datagrams that could not be routed at all: %llu",
             (unsigned long long)stats.udp_unroutable);
        /* ⚠️ TWO NUMBERS LEFT THIS LINE, AND BOTH FOR THE REASON THE PAGE ABOVE ALREADY GIVES.
         *
         * `spliced` was printed here as well as on the `direct` line above, so on REALITY it said
         * the same thing twice — and on Hysteria2, where nothing is ever spliced, it said zero
         * forever. `hops` is the mirror image: port hopping is a Hysteria2 feature, `stats.hops` is
         * incremented in exactly one place and that place is on the QUIC path, so on the REALITY
         * plane this printed a counter that cannot move.
         *
         * That is the fault the note before `reads` describes and claims to have finished with,
         * still standing eighty lines later on the line nobody re-read. A number that cannot move
         * in the configuration in front of you is not a zero, it is noise wearing a zero's clothes:
         * the reader has to know the code to know which it is, and if they knew the code they would
         * not be reading the summary. */
        note("datagrams %llu bytes (up %llu, down %llu) | datagram share %llu%% | dropped going up "
             "%llu",
             (unsigned long long)udp, (unsigned long long)stats.udp_bytes_up,
             (unsigned long long)stats.udp_bytes_down,
             (unsigned long long)(all ? udp * 100u / all : 0),
             (unsigned long long)stats.udp_dropped);
#if LC_HYSTERIA
        if (on_hy_plane)
            note("hops %llu", (unsigned long long)stats.hops);
#endif
        /* Said again next time there is something to say, which is what makes the line worth
         * reading: one drop after a quiet hour is not the same event as one in a burst of eight
         * hundred, and a message printed once at startup would not tell them apart. */
        udp_drop_said = 0;
    }
}

/* Every live session, so that something can walk them. Sessions are reached from events by pointer,
 * which is enough for traffic but not for anything that has to happen when NOTHING arrives — and a
 * connection that hangs half-built is exactly that case.
 *
 * ⚠️ AND IT HAS NO CEILING, as the reference has none. It held 256 a worker, streams and datagrams
 * together, and the 257th connection was closed as soon as it was accepted — a household with a
 * torrent client or a game launcher open reaches that, and Xray and hysteria never refuse one:
 * each is a goroutine started for whatever the listener accepts. What bounds it now is what bounds
 * them: memory, which session_new asks for before every session, and descriptors, raised at start
 * the way Go raises them (see main). The table doubles when it is full and does not shrink — a slot
 * is a pointer. */
static session **sessions;
static unsigned  sessions_cap;
static unsigned  session_count;

/* OUT OF DESCRIPTORS, THE LISTENER RESTS HALF A SECOND, as Xray's accept loop does: an Accept error
 * saying "too many" is logged and followed by `time.Sleep(time.Millisecond * 500)`, then Accept again
 * (vendor/Xray-core/transport/internet/tcp/hub.go:92-103). The connection stays queued in the kernel
 * meanwhile and is taken when a descriptor frees — it is not refused. Taken off the loop for that
 * half second because the loop is level-triggered and would otherwise be handed the same event at
 * once, forever; taken off by removal and put back by adding, because a listener shared between
 * workers is registered EPOLLEXCLUSIVE, which a modification may not touch.
 *
 * ⚠️ UNTIL 2026-09-27 a descriptor was held in reserve for this, and on EMFILE it was spent to
 * accept the queued connection and close it at once — a refusal the reference never makes. */
static uint64_t listen_resume_at;
static int      listen_resume_failed;

/* Returns 1 when the failure was "too many" and the listener now rests. */
static int accept_exhausted(lc_loop *loop, int listen_fd)
{
    if (errno != EMFILE && errno != ENFILE)
        return 0;
    if (listen_resume_at == 0u) {
        (void)lc_loop_del(loop, listen_fd);
        listen_resume_at = lc_now_ms() + 500u;
        listen_resume_failed = 0;
        note("out of descriptors: accepting again in half a second");
    }
    return 1;
}

/* Removing an EPOLLEXCLUSIVE listener requires a fresh ADD to resume it. That
 * ADD can itself run out of memory/watch entries. Keep the retry armed until
 * registration succeeds; clearing it first leaves a live but deaf process.
 * Existing sessions keep their watches and continue while this listener rests. */
static void accept_resume(lc_loop *loop, int listen_fd, int shared, uint64_t now)
{
    if (listen_resume_at == 0u || now < listen_resume_at)
        return;
    if (lc_loop_add(loop, listen_fd, LC_EV_READ | (shared ? LC_EV_EXCLUSIVE : 0u), NULL) != 0) {
        listen_resume_at = now + 500u;
        if (!listen_resume_failed)
            note("cannot watch the listener again: %s; retrying in half a second", strerror(errno));
        listen_resume_failed = 1;
        return;
    }
    listen_resume_at = 0u;
    listen_resume_failed = 0;
}

/* ---- the Hysteria2 plane ----------------------------------------------------
 *
 * One QUIC connection for the whole process, and every proxied connection a stream on it. That is
 * the opposite of the REALITY plane, where each connection gets a socket and a TLS handshake of its
 * own, and it is why the two do not share a session type beyond the queues.
 *
 * It also means one failure takes everything with it: when this connection dies, every session
 * riding it dies too. Hence the reconnection below, and hence the plane being chosen once at
 * startup rather than per connection. */
#if LC_HYSTERIA
/* ONE CONNECTION TO THE NODE, and there can be more than one of them alive at once — the reference's
 * shape, not a pool of this client's.
 *
 * The reference's client is reconnectableClientImpl: it holds one Client, the one every new request
 * uses, and lets go of it when a call on it comes back ClosedError — `rc.client = nil`, and the next
 * request dials a new one (vendor/hysteria/core/client/reconnect.go:63-88). Letting go is not
 * closing. The client it dropped keeps its QUIC connection, its streams and its UDP sessions, and
 * they go on carrying until they end or the connection does. ClosedError comes from a stream the
 * node ended before its answer, or an answer that does not parse (wrapIfConnectionClosed over
 * ReadTCPResponse, vendor/hysteria/core/client/client.go:216-220, :251-262) as much as from QUIC
 * failing — and in the first two cases the connection is alive, kept so by its keep-alive, until the
 * node or its idle clock ends it.
 *
 * So `hy.link` is the connection new requests use, and `hy.left` the ones let go of that still
 * carry. A session belongs to the connection whose generation it was stamped with, for its whole
 * life. */
typedef struct {
    lc_qconn c;
    int      up;   /* connected and authenticated */
    int      udp;  /* the node said it would relay datagrams for us */
    int      fd;   /* what the loop is watching, so it can be dropped when the connection is remade */
    /* The connection's send queue wakes the loop through this when it frees an entry, so that a
     * write pass that stopped on a full queue goes on at once — the reference's run loop waking on
     * sendQueueAvailable. It carries hy_tag like `fd`, and what it wakes is the same turn. The
     * socket itself is no longer watched for writability: the queue's writer thread waits on it. */
    int      wake_fd;
    /* The last step of hy_turn read datagrams its sessions have not been offered: the loop takes its
     * next turn without sleeping — see the end of hy_turn. */
    int      again;

    /* Which connection this is. Every session is stamped with it when its stream is opened, and
     * anything carrying an older stamp is not merely stale — it addresses a stream table that has
     * been wiped and refilled by somebody else's streams.
     *
     * Without it the guarantee rests entirely on hy_drop closing every last session before a new
     * connection is made. It does. But that makes correctness a property of one loop being
     * exhaustive rather than of the structure, and a handle that outlives its connection then
     * points at whatever took the slot — with the per-slot generation reset to zero, because the
     * new connection's table starts fresh. A stamp makes the mistake impossible to make. */
    uint64_t gen;
} hy_link;

static struct {
    /* The connection new requests use — reconnectableClientImpl's `client`. Always there, up or
     * not: what "no client" means is `up` clear. */
    hy_link  *link;
    /* The connections let go of that still carry their sessions. */
    hy_link **left;
    unsigned  nleft;

    int      on;   /* this is the plane in use */
    /* The last generation handed out; each connection takes the next. */
    uint64_t gen;

    const char *node;
    uint16_t    port;
    const char *sni;

    /* Both secrets are held here rather than pointed at in argv. The obfuscation password was a
     * pointer INTO the command line, so it stayed legible in /proc/PID/cmdline — mode 0444, and
     * hidepid is not on by default on OpenWrt — for the weeks this process runs. It gates the node's
     * whole UDP port: without it the node answers nothing at all, so it is the outermost layer of
     * the node's concealment, and the three probes that borrow this plane already copy it out and
     * overwrite the argument. The one process that runs for weeks did not. */
    char     obfs[LC_OBFS_PASSWORD_MAX];
    char     password[LC_OBFS_PASSWORD_MAX];
    uint64_t rx_rate;
    /* The build without this plane cannot name the constant and spells the number out; this is what
     * stops the two from drifting. */
    _Static_assert(LC_OBFS_PASSWORD_MAX == 512u,
                   "the plane-less build spells this number out; change both or neither");

    /* The node's expected certificate digest, when the operator supplied one. Kept across reconnects
     * because it identifies the node rather than the connection. */
    uint8_t pin[LC_QTLS_PIN];
    int     have_pin;
    /* Set by `-p -`: the operator has been asked and has answered. See the refusal in main. */
    int     pin_waived;

    /* HOW FAR ALONG BUILDING THE CONNECTION IS, because building it no longer stops the world.
     *
     * 0 nothing in progress, 1 waiting for the QUIC handshake, 2 waiting for the node to answer the
     * authentication request. Both waits used to be loops of their own inside hy_connect — up to ten
     * seconds each, during which this single-threaded client served no session, no datagram and no
     * timer, on precisely the path where something had already gone wrong. See hy_advance. */
    int               pending;
    /* When the handshake runs out of LC_HY_HANDSHAKE_MS — the idle half is lc_qconn_silent_ms. */
    uint64_t          pending_deadline;
    lc_h3_auth_result pending_auth;
    /* Arrival order of the requests waiting for a connection (ST_HYWAIT): the order they queue on the
     * reference's mutex, and so the order they are served — or, one at a time, fail. */
    uint64_t          wait_seq;
    /* The connection died and no request has tripped over it yet. The reference keeps the dead client
     * as rc.client until a call on it comes back ClosedError: that request fails, the client is set to
     * nil, and only the NEXT request dials (vendor/hysteria/core/client/reconnect.go:63-88). */
    int               dead;

    /* The port range to move across, when one was asked for. Kept here rather than handed straight
     * to the connection because the argument is parsed in both builds and the connection exists in
     * only one of them. */
    lc_hop_ports hop_ports;
    unsigned     hop_min, hop_max;
    /* Gecko, the shape obfuscation that wraps Salamander. Zero means off; see quic/gecko.h. */
    unsigned gecko_min, gecko_max;
    /* NOT parroting Chrome's QUIC stack — `-c off`; zero, the default, parrots, as the reference
     * does. See lc_qconn_chrome_off. */
    int plain;
} hy;

static endpoint hy_tag = { NULL, 0 };

/* The connection a session rides: the one its generation names, while that one still carries; NULL
 * once it has gone. */
static hy_link *hy_link_of(const session *s)
{
    if (s->hy_gen == 0)
        return NULL;
    if (hy.link->up && hy.link->gen == s->hy_gen)
        return hy.link;
    for (unsigned i = 0; i < hy.nleft; i++)
        if (hy.left[i]->gen == s->hy_gen)
            return hy.left[i];
    return NULL;
}

/* Whether any connection's datagram queue is too full to take what the shared socket might hold
 * next — see the gate in the loop. A datagram read goes to whichever connection its session rides,
 * and that is not known until it is read. */
static int hy_udp_full(void)
{
    if (hy.link->up && hy.link->c.dq_count + LC_QUDP_FRAGS > LC_QUDP_QUEUE)
        return 1;
    for (unsigned i = 0; i < hy.nleft; i++)
        if (hy.left[i]->c.dq_count + LC_QUDP_FRAGS > LC_QUDP_QUEUE)
            return 1;
    return 0;
}

/* Whether any connection's last step read datagrams its sessions have not been offered. */
static int hy_again(void)
{
    if (hy.link->up && hy.link->again)
        return 1;
    for (unsigned i = 0; i < hy.nleft; i++)
        if (hy.left[i]->again)
            return 1;
    return 0;
}

/* The first client, made before anything can ask for it: `up` clear, nothing on the loop. */
static int hy_setup(void)
{
    hy.link = calloc(1, sizeof *hy.link);
    if (hy.link == NULL)
        return -1;
    hy.link->fd = -1;
    hy.link->wake_fd = -1;
    return 0;
}

/* The reader thread's end of the conversation: a pipe it writes one byte to, and a tag so that the
 * loop's dispatch can tell that byte apart from a session. See net/reader.h. */
static int      reader_wake[2] = { -1, -1 };
static endpoint reader_tag = { NULL, 0 };
#else
/* Without the plane: the same shape, never used. The argument parser fills it in either build and
 * every call site below compiles unchanged; what refuses is one check in main, so that asking for
 * a plane this build does not have is answered rather than quietly ignored.
 *
 * The struct minus the connection is about a hundred and sixty bytes of memory a REALITY-only
 * client never touches. That is the price of the two builds reading as one program, and it is the
 * cheap side of the trade — the expensive one is two loops that drift apart. */
static struct {
    int         on, up, udp, fd, wake_fd;
    const char *node, *sni;
    uint16_t    port;
    /* Five hundred and twelve spelled out rather than LC_OBFS_PASSWORD_MAX, for the same reason the
     * pin below is spelled out: this build does not compile quic/obfs.c and has never seen the
     * header that names it. Both fields are only ever written by the argument parser, which refuses
     * anything that does not fit, so a disagreement with the other build costs a refusal and not a
     * overrun — and there is a _Static_assert beside the Hysteria copy tying the two together. */
    char        obfs[512];
    char        password[512];
    uint64_t    rx_rate;
    /* Thirty-two spelled out rather than LC_QTLS_PIN, because this build does not compile the module
     * that defines it. Every use goes through sizeof hy.pin, so the two cannot disagree about the
     * length in any way that matters. */
    uint8_t     pin[32];
    int         have_pin;
    int         pin_waived;
    lc_hop_ports hop_ports;
    unsigned    hop_min, hop_max;
    unsigned    gecko_min, gecko_max;
    int         plain;
    /* Present for the same reason as the rest of this struct: the shared code reads the same in
     * both builds, and without the plane nothing ever sets it. */
    int         pending;
    /* Present here only so that the shared code reads the same in both builds — see the note above.
     * A REALITY-only client never opens a stream on the node's connection, so this stays zero and
     * every `s->hy_gen == hy.gen` it takes part in is a comparison of two zeroes. */
    uint64_t    gen;
} hy;

static int hy_setup(void) { return 0; }

static endpoint hy_tag = { NULL, 0 };
#endif

static session *session_new(void)
{
    /* NOTHING ASKS WHETHER THE MACHINE CAN SPARE IT, as nothing asks in the reference: a session is
     * taken while the allocator gives one, and when the kernel runs out it is the kernel that
     * decides. A reserve of our own stood here — refusing a connection while less than a tenth of
     * the machine was available — and was taken out on the maintainer's word, 29.09 (L1): it refused the
     * reference's connections on a router with room for them whenever anything else, /tmp included,
     * held that tenth. */
    /* A slot for it, the table doubled first when every one is taken — closed sessions keep theirs
     * until sessions_reap, and are counted until then. */
    if (session_count == sessions_cap) {
        unsigned  cap = sessions_cap > 0u ? sessions_cap * 2u : 64u;
        session **grown = realloc(sessions, (size_t)cap * sizeof *grown);
        if (grown == NULL)
            return NULL;
        memset(grown + sessions_cap, 0, (size_t)(cap - sessions_cap) * sizeof *grown);
        sessions = grown;
        sessions_cap = cap;
    }

    session *s = calloc(1, sizeof *s);
    if (s == NULL)
        return NULL;
    /* The only place a live session is zeroed; the other memset is the one before free. */
    s->to_up.buf = s->to_up_buf;
    s->to_up.cap = sizeof s->to_up_buf;
    s->to_lan.buf = s->to_lan_buf;
    s->to_lan.cap = sizeof s->to_lan_buf;
    for (unsigned i = 0; i < sessions_cap; i++) {
        if (sessions[i] == NULL) {
            sessions[i] = s;
            break;
        }
    }
    s->pipe_rd = -1;
    s->pipe_wr = -1;
    s->lan_tag.s = s;
    s->lan_tag.is_lan = 1;
    s->up_tag.s = s;
    s->up_tag.is_lan = 0;
    s->spider_tag.s = s;
    s->spider_tag.is_lan = 2;
    s->spider_wake_fd = -1;
    s->lan_fd = -1;
    s->up_fd = -1;
    s->reply_wait_fd = -1;
    s->rx = s->rx_small;
    s->rx_cap = sizeof s->rx_small;
    session_count++;
    return s;
}

static void spider_worker_stop(session *s)
{
    if (!s->spider_worker_on && !s->spider_request_worker_on)
        return;
    lc_spider_fetch_stop(s->fetch);
    if (s->spider_worker_on)
        (void)pthread_join(s->spider_worker, NULL);
    if (s->spider_request_worker_on)
        (void)pthread_join(s->spider_request_worker, NULL);
    s->spider_worker_on = 0;
    s->spider_request_worker_on = 0;
}

/* Completion retires an HTTP executor, not its fetch/readLoop/TLS connection.
 * The flag is published only on the thread's terminal path; its remaining
 * work is a nonblocking eventfd notification and return, never protocol work. */
static int spider_workers_reap(session *s)
{
    if (s->spider_worker_on &&
        atomic_load_explicit(&s->spider_worker_done, memory_order_acquire)) {
        int error = pthread_join(s->spider_worker, NULL);
        if (error != 0) {
            note("spider completion fd=%d: Do worker join failed (%d: %s)",
                 s->up_fd, error, strerror(error));
            return -1;
        }
        s->spider_worker_on = 0;
    }
    if (s->spider_request_worker_on &&
        atomic_load_explicit(&s->spider_request_done, memory_order_acquire)) {
        int error = pthread_join(s->spider_request_worker, NULL);
        if (error != 0) {
            note("spider completion fd=%d: request worker join failed (%d: %s)",
                 s->up_fd, error, strerror(error));
            return -1;
        }
        s->spider_request_worker_on = 0;
    }
    return 0;
}

/* Tearing a session down happens in two steps, and the split is not tidiness.
 *
 * epoll hands back a batch of events, and both of a session's descriptors can be in the same batch.
 * If closing freed the memory at once, the first event could end the session and the second would
 * then read a freed pointer — the use-after-free the loop's design goes out of its way to avoid,
 * walked back in through the door. So closing detaches and releases everything the kernel knows
 * about, and the memory itself goes back only once the whole batch has been dealt with.
 *
 * The same split is what lets the timeout sweep run at all: it ends sessions while a batch of
 * events referring to them may still be pending. */

/* The destination a reply came from, or NULL. Compared as text because that is what the frame
 * carries and what was put in it — no resolution, no normalisation, no second spelling to disagree
 * with the first. */
static struct udp_dest *dest_find(session *s, const char *host, uint16_t port)
{
    if (s->dests == NULL || host == NULL || host[0] == '\0')
        return NULL;
    for (unsigned i = 0; i < s->dest_count; i++) {
        if (s->dests[i].port == port && strcmp(s->dests[i].host, host) == 0)
            return &s->dests[i];
    }
    return NULL;
}

/* The destination this datagram is for, added if it is new — the table doubling when it is full —
 * and NULL only when there is no memory to add it. The pointer lasts until the next call adds one. */
/* A FAILURE OF THIS CLIENT'S OWN ENDS THE SESSION WITHOUT A WORD TO THE NODE: memory that could not
 * be had, which is where the reference's process ends — Go's runtime ends the program when an
 * allocation fails, and the kernel then closes its sockets with nothing in front of the FIN. So
 * session_close sends no close_notify for it, the one thing it would otherwise add; the handshake's
 * half is hs_own in tls/client.c. Returns -1 for the caller to pass on. */
static int own_failure(session *s)
{
    s->own_fail = 1;
    return -1;
}

static struct udp_dest *dest_for(session *s, const char *host, uint16_t port)
{
    struct udp_dest *d = dest_find(s, host, port);
    if (d != NULL)
        return d;
    if (s->dests == NULL)
        return NULL;

    if (s->dest_count == s->dest_cap) {
        unsigned         cap = s->dest_cap * 2u;
        struct udp_dest *grown = realloc(s->dests, (size_t)cap * sizeof *grown);
        if (grown == NULL)
            return NULL;
        s->dests = grown;
        s->dest_cap = cap;
    }
    d = &s->dests[s->dest_count++];
    snprintf(d->host, sizeof d->host, "%s", host);
    d->port = port;
    d->reply_fd = -1;
    return d;
}

/* EIGHT BYTES NAMING THIS CLIENT TO THE NODE, which is what buys full-cone NAT.
 *
 * The node keeps one UDP mapping per value it sees here — `XUDPManager.Map[meta.GlobalID]`
 * (vendor/Xray-core/common/mux/server.go:195-227) — so the same client reaching a second address
 * reuses the mapping instead of getting a fresh one. That reuse IS cone behaviour, and without it a
 * household gets symmetric NAT: calls, games and WebRTC all pay for it.
 *
 * ⚠️ IT MUST BE PER CLIENT AND NOT PER TUNNEL. One value shared by every device behind the router
 * would fold them all into a single mapping at the node, which is worse than the zeros this used to
 * send — those the node is required to ignore, and ignoring is at least correct.
 *
 * The reference derives its own from the inbound source with a keyed BLAKE3 (xudp.go:65-79). The
 * VALUE need not match: the node treats it as an opaque map key and never recomputes it. What must
 * hold is that it is stable for one source, different between sources, and not a stable identifier
 * for the source across runs — hence a key drawn once at startup rather than a constant. HKDF is
 * used because it is in every build; BLAKE2b is only linked into the Hysteria one.
 *
 * The port is part of the source, exactly as it is upstream: a NAT tuple is an address and a port. */
static uint8_t gid_key[32];
static int     gid_key_ready;

/* Drawn once, and drawn BEFORE the workers exist.
 *
 * ⚠️ IT USED TO BE A LAZY STATIC INSIDE client_global_id, which was correct while there was one
 * process and silently wrong the moment there were several: each worker would have drawn its own
 * key on first use, so the same household client reaching two workers — one datagram socket per
 * source port, and the kernel hashes those to different workers — would have been given two
 * different global ids. The node keys a UDP mapping on that value, so it would have seen two
 * clients where there is one, and full-cone NAT is exactly what the id exists to buy. Seeded from
 * main before the fork, inherited identical by every worker. */
static void gid_key_init(void)
{
    if (gid_key_ready)
        return;
    if (lc_rnd(gid_key, sizeof gid_key) == 0)
        gid_key_ready = 1;
}

static void client_global_id(const struct sockaddr_storage *peer, socklen_t len, uint8_t out[8])
{
    memset(out, 0, 8);
    gid_key_init();
    if (!gid_key_ready)
        return; /* Zeros: legal, ignored by the node, and better than a predictable value. */

    /* gid_key directly, not through a local pointer: `sizeof` on a pointer is four bytes and
     * compiles without a word, which would have fed HKDF an eighth of the key it was given. */
    uint8_t prk[LC_HASH_MAX];
    if (lc_hkdf_extract(LC_SHA256, gid_key, sizeof gid_key, (const uint8_t *)peer, (size_t)len,
                        prk) != 0)
        return;
    memcpy(out, prk, 8);
    lc_wipe(prk, sizeof prk);
}

/* Which socket answers a reply that says it came from this address — the reference's writer, on
 * either plane — or -1 when the one it needs cannot be made, which drops that datagram.
 *
 *   Not transparent (the configured form, `-u PORT@HOST:PORT`, where the first destination has no
 *   socket of its own): the listener, whoever answered — dokodemo's SequentialWriter over the
 *   inbound connection (vendor/Xray-core/proxy/dokodemo/dokodemo.go:165-166).
 *
 *   Hysteria2: the pair's own socket, whoever answered. tproxy's forwarding writes every datagram
 *   the session receives to the connection it dialled from the pair's destination, and never looks
 *   at where it came from (vendor/hysteria/app/internal/tproxy/udp_linux.go:97-110).
 *
 *   REALITY: the socket bound to that address, made the first time it is needed — Xray's
 *   PacketWriter opens a FakeUDP for every IP address that answers, keeps it in its map for the
 *   session, and when one cannot be made drops that datagram and tries again with the next
 *   (vendor/Xray-core/proxy/dokodemo/dokodemo.go:230-253). An address that is not an IP — a name,
 *   or none — goes out of the first destination's socket, its `w.conn` (:254-261).
 *
 * ⚠️ AN ADDRESS THIS SESSION NEVER SENT TO WAS NOT ANSWERED, on either plane, on the ground that it
 * could not be attributed and would be an unasked-for packet from a stranger. Both references answer
 * it. It arrived on this client's stream or session, which is attribution enough, and full-cone NAT
 * — what the global id in client_global_id is sent to buy — means exactly that an address the
 * client never asked may reach it: a STUN server's second address, a game's relay, a peer that
 * learnt the mapping from somebody else. Every one of those was dropped here and delivered there. */
static int reply_socket_for(session *s, const char *host, uint16_t port)
{
    if (s->dest_count == 0u)
        return -1;
    /* Not transparent: the listener answers. Asked of the flag and not of dests[0]'s socket, which
     * a failed reply may have closed — see reply_failed. */
    if (s->udp_unaddressed)
        return s->lan_fd;
    if (hy.on)
        return s->dests[0].reply_fd;

    struct udp_dest *d = dest_find(s, host, port);
    if (d == NULL) {
        uint8_t ip[16];
        if (host == NULL ||
            (inet_pton(AF_INET, host, ip) != 1 && inet_pton(AF_INET6, host, ip) != 1))
            return s->dests[0].reply_fd;
        d = dest_for(s, host, port);
        if (d == NULL)
            return own_failure(s);
    }
    if (d->reply_fd < 0) {
        /* Always a literal by now, and a literal always fits: INET6_ADDRSTRLEN is what the field is. */
        lc_addr a;
        size_t  hl = strlen(d->host);
        if (hl >= sizeof a.host)
            return -1;
        memset(&a, 0, sizeof a);
        memcpy(a.host, d->host, hl);
        a.port = d->port;
        d->reply_fd = lc_udp_reply_socket(&a);
    }
    return d->reply_fd;
}

/* ---- the REALITY plane's ActivityTimer ----
 *
 * One per session, and the three operations are the reference's three: SetTimeout, Update and the
 * periodic check. See CONNECTION_IDLE_MS for what each is and where Xray calls it. */

/* `SetTimeout`: marks activity and checks at once, which consumes the mark — so the next check comes
 * one timeout from now and fires unless something moves before it. */
static void act_set(session *s, uint64_t ms)
{
    s->act_ms = ms;
    s->act_seen = 0;
    s->act_next = lc_now_ms() + ms;
}

/* `Update`. */
static void act_update(session *s)
{
    s->act_seen = 1;
}

/* The periodic check. Returns 1 when the timer fires: no activity since the check before. */
static int act_fired(session *s, uint64_t now)
{
    if (s->act_ms == 0u || now < s->act_next)
        return 0;
    if (!s->act_seen)
        return 1;
    s->act_seen = 0;
    s->act_next = now + s->act_ms;
    return 0;
}

/* The UDP inbound's checker, one per listener as the reference has one per worker. */
static struct {
    int      running;
    uint64_t next;
} udp_checker;

/* `lastActivityTime`, stored the way the reference stores it. */
static void udp_seen(session *s)
{
    s->udp_seen_s = lc_now_ms() / 1000u;
}

/* Holds a datagram until it can be written: in arrival order, whatever its destination, and full
 * means drop, which is what the reference's inbound pipe does with DiscardOverflow.
 *
 * ⚠️ "WITHIN ONE DESTINATION THE NEWEST REPLACES THE ONE WAITING" STOOD HERE, and nothing below does
 * it — struct udp_pend records why the rule was taken out, and the sentence outlived it. */
/* The largest datagram the session's writer carries: xudp's `length+666 > buf.Size`
 * (vendor/Xray-core/common/xudp/xudp.go:99-102), command 0x02's `length+2 > buf.Size`
 * (vendor/Xray-core/proxy/vless/encoding/addons.go:100-102), Hysteria2's own. */
static size_t udp_max_datagram(const session *s)
{
    if (s->hy_h != 0 || hy.on)
        return UDP_MAX_DATAGRAM;
    return s->plain_udp ? XUDP_READ_SIZE - 2u : XUDP_MAX_DATAGRAM;
}

static void pend_put(session *s, const char *host, uint16_t port, const uint8_t *data, size_t len)
{
    size_t host_len = strlen(host);
    /* Empty is refused except as a Hysteria2 pair's first packet, which the reference sends as it is
     * (see hy_send_datagram); on REALITY the hub never lets one through. */
    int empty_ok = (s->hy_h != 0 || hy.on) && s->pend_q != NULL && s->pend_q->count == 0u &&
                   !s->hy_first_sent;
    if (s->pend_q == NULL || (len == 0u && !empty_ok) ||
        len > udp_max_datagram(s) ||
        host_len == 0u ||
        host_len > 255u) {
        stats.udp_unroutable++;
        return;
    }
    size_t need = 1u + host_len + 2u + 2u + len;
    /* What a write under way has taken has left the reference's pipe — its ReadMultiBuffer emptied it —
     * so only what is behind that write counts against the pipe's size. The buffer is twice the size
     * so that both fit. */
    size_t held = s->pend_q->len - (s->up_n > 0u ? s->up_end : 0u);
    if (held + need > UDP_PEND_BYTES) {
        /* Full. The reference discards the overflow and keeps what it already holds, which is the
         * only choice that preserves ORDER — dropping from the front to make room would deliver a
         * stream with a hole in the middle and no way for the far end to know. */
        stats.udp_dropped++;
        return;
    }

    uint8_t *p = s->pend_q->buf + s->pend_q->len;
    *p++ = (uint8_t)host_len;
    memcpy(p, host, host_len);
    p += host_len;
    *p++ = (uint8_t)(port >> 8);
    *p++ = (uint8_t)port;
    *p++ = (uint8_t)(len >> 8);
    *p++ = (uint8_t)len;
    memcpy(p, data, len);
    s->pend_q->len += need;
    s->pend_q->count++;
}

#if LC_HYSTERIA
/* Walks the queue in arrival order, handing each datagram and its own destination to `send`.
 * Stops at the first refusal and empties the queue either way: what is left after a failed send
 * belongs to a session that is going down.
 *
 * The Hysteria2 plane's flush only. Its reference hands every datagram to the QUIC connection as it
 * comes and has no pipeline of writers to reproduce; the REALITY plane's datagrams go through udp_pump,
 * which does. */
static int pend_flush(session *s, int (*send)(session *, const char *, uint16_t, const uint8_t *,
                                              size_t))
{
    int rc = 0;
    if (s->pend_q == NULL)
        return 0;

    const uint8_t *p = s->pend_q->buf;
    const uint8_t *end = p + s->pend_q->len;
    while (p < end && rc == 0) {
        size_t host_len = *p++;
        if ((size_t)(end - p) < host_len + 4u)
            break;
        char host[256];
        memcpy(host, p, host_len);
        host[host_len] = '\0';
        p += host_len;
        uint16_t port = (uint16_t)((uint16_t)p[0] << 8 | p[1]);
        p += 2;
        size_t dlen = (size_t)p[0] << 8 | p[1];
        p += 2;
        if ((size_t)(end - p) < dlen)
            break;
        rc = send(s, host, port, p, dlen);
        p += dlen;
    }
    s->pend_q->len = 0;
    s->pend_q->count = 0;
    return rc;
}
#endif

/* A dial to a node given by name, ended wherever it is: the lookup it waits on is let go, a connect
 * in the air is closed. What `up_fd` held was the dial's own descriptor, which goes with it. */
static void dial_drop(lc_loop *l, session *s)
{
    if (s->dial == NULL)
        return;
    lc_loop_del(l, s->up_fd);
    lc_dial_free(s->dial);
    s->dial = NULL;
    s->up_fd = -1;
}

/* The same split is what lets the timeout sweep run at all: it ends sessions while a batch of
 * events referring to them may still be pending. */
static void session_finish(lc_loop *l, session *s)
{
    if (s == NULL)
        return;
    s->closing = 1;
    s->close_by = 0;

    /* Stop wakes every form of the consumer wait; join precedes fetch/session release. */
    spider_worker_stop(s);
    free(s->spider_write);
    s->spider_write = NULL;
    if (s->spider_wake_fd >= 0) {
        lc_loop_del(l, s->spider_wake_fd);
        close(s->spider_wake_fd);
        s->spider_wake_fd = -1;
    }

#if LC_HYSTERIA
    /* THE READER LETS GO FIRST, AND IT IS SYNCHRONOUS. lc_reader_del removes the descriptor from the
     * reader's epoll, goes through the stage's lock, and waits out the batch of events the reader is
     * in the middle of, which may still name this session — so when it returns, this session is this
     * thread's alone and everything below is free to close the descriptor and release the memory.
     * Doing this in any other order is a use-after-free with a thread on the other end of it, and
     * without the last of the three it was one anyway: see lc_reader_del. */
    lc_reader_del(&s->stage);
#endif
    /* A pooled connection that never finished its dial. `is_spare` is cleared the moment a request
     * takes one, and the other end a pooled connection can reach while still flagged — a taker finding
     * it expired — counts itself in spare_take; everything else arrives here, which is every way a
     * dial fails. */
    if (s->is_spare && s->st != ST_SPARE)
        stats.spare_failed++;
    /* A datagram session borrows the one shared socket; closing it would take every other UDP
     * client down with it, and deregistering it would stop the listener. */
    if (s->is_udp)
        s->lan_fd = -1;
    /* Told rather than dropped: a stream simply abandoned holds a slot and a window at the node
     * until the whole connection times out, and there are only so many of either. */
    if (s->hy_h != 0) {
#if LC_HYSTERIA
        /* Told rather than dropped — but only to the connection that issued the handle. To a newer
         * one the same number means somebody else's stream, and closing that would be this plane's
         * own use-after-free, one level above the memory. */
        hy_link *k = hy_link_of(s);
        if (k != NULL) {
            if (s->is_udp)
                lc_qconn_udp_close(&k->c, s->hy_h);
            else
                lc_qconn_tcp_close(&k->c, s->hy_h);
        }
#endif
        s->hy_h = 0;
        s->hy_read = 0;
    }
    /* The fetch goes with the session that was making it, harvest and all. */
    lc_spider_fetch_free(s->fetch);
    s->fetch = NULL;
    /* A dial still in the air holds no connection yet, and nothing to say CLOSE_NOTIFY on. */
    dial_drop(l, s);
    if (s->up_fd >= 0) {
        lc_loop_del(l, s->up_fd);
        /* The reference would have left bytes in the socket — read here ahead of it — so its close
         * goes out as a reset, and so does this one. See node_read_ahead. DIVERGES: O3. */
        if (s->rin_ahead > 0u) {
            struct linger lg = { 1, 0 };
            (void)setsockopt(s->up_fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
        }
        if (s->gc_park)
            gcemu_park(s->up_fd); /* the last attempt's failed handshake — see gcemu */
        else
            close(s->up_fd);
        s->up_fd = -1;
        s->gc_park = 0;
    }
    /* VLESS Process defers the node Close; DokodemoDoor.Process waits for DispatchLink
     * before tcpWorker.callback closes the client (vendor/Xray-core/proxy/vless/outbound/
     * outbound.go, proxy/dokodemo/dokodemo.go, app/proxyman/inbound/worker.go).
     * Finish the node transport before releasing the client, also after a failed or
     * expired close_notify write. This orders local closes, not packet arrival on two paths. */
    if (s->lan_fd >= 0) {
        /* close removes the watch unconditionally. Already-returned events retain the session
         * until batch reap and are rejected by closing, even if DEL fails. */
        lc_loop_del(l, s->lan_fd);
        close(s->lan_fd);
        s->lan_fd = -1;
    }
    /* Every address this session answered as. One socket per destination is not an accident of the
     * design but a requirement of it — see the table's own note — so ending the session ends all of
     * them, and the table goes with them rather than at the reap: a descriptor held past the close
     * is a descriptor the kernel still counts. */
    if (s->dests != NULL) {
        for (unsigned i = 0; i < s->dest_count; i++) {
            if (s->dests[i].reply_fd >= 0)
                close(s->dests[i].reply_fd);
        }
        free(s->dests);
        s->dests = NULL;
        s->dest_count = 0;
    }
    free(s->pend_q);
    s->pend_q = NULL;
    free(s->plain_pkt);
    s->plain_pkt = NULL;
    if (s->reply_wait_fd >= 0) {
        lc_loop_del(l, s->reply_wait_fd);
        close(s->reply_wait_fd);
        s->reply_wait_fd = -1;
    }
    free(s->reply_held);
    s->reply_held = NULL;
    if (s->pipe_rd >= 0) {
        close(s->pipe_rd);
        s->pipe_rd = -1;
    }
    if (s->pipe_wr >= 0) {
        close(s->pipe_wr);
        s->pipe_wr = -1;
    }
    lc_client_hs_free(s->hs);
    s->hs = NULL;
    lc_client_free(&s->cl);
    lc_post_free(&s->post);
    if (s->rx != s->rx_small) {
        lc_wipe(s->rx, s->rx_cap);
        free(s->rx);
        s->rx = s->rx_small;
        s->rx_cap = sizeof s->rx_small;
        s->rx_len = 0;
    }
}

/* uTLS Conn.Close/closeNotify (vendor/utls/conn.go) writes one alert with a five-second
 * deadline before closing the transport. VLESS defers that Close until Process returns.
 * Preserve the write across nonblocking readiness events, keeping both endpoints alive
 * until it finishes. A queued application write still means immediate close, as in
 * uTLS's activeCall check: an alert after an unsent record has the wrong sequence.
 * XUDP's PacketWriter has no Close and contributes no additional end frame. */
static void session_close(lc_loop *l, session *s)
{
    if (s == NULL)
        return;
    if (!s->closing) {
        s->closing = 1;
        spider_worker_stop(s);
        /* Xray v26.10.31 proxy.go::SuppressOuterCloseNotify closes the raw
         * transport once either Vision direction has entered direct copy. */
        if (s->direct_in || s->raw_writer ||
            s->up_fd < 0 || s->st == ST_HANDSHAKE || s->st == ST_CONNECTING ||
            q_pending(&s->to_up) != 0 || s->own_fail) {
            session_finish(l, s);
            return;
        }
        s->close_by = lc_now_ms() + 5000u;
        uint8_t rec[LC_CLIENT_ALERT_MAX];
        size_t n = lc_client_alert_record(&s->cl, LC_CLIENT_ALERT_CLOSE_NOTIFY, rec, sizeof rec);
        if (n == 0 || q_push(&s->to_up, rec, n) != 0) {
            session_finish(l, s);
            return;
        }
    } else if (s->close_by == 0) {
        return;
    }
    if (lc_now_ms() >= s->close_by || q_flush(&s->to_up, s->up_fd) != 0 ||
        q_pending(&s->to_up) == 0) {
        session_finish(l, s);
        return;
    }
    /* The application is done. Remove its watches to avoid readable/HUP spins
     * while the node alone owns the remaining close write. The LAN FIN follows it. */
    if (s->lan_on_loop && !s->is_udp) {
        lc_loop_del(l, s->lan_fd);
        s->lan_on_loop = 0;
    }
    if (s->spider_wake_fd >= 0)
        lc_loop_del(l, s->spider_wake_fd);
    if (s->reply_wait_fd >= 0)
        lc_loop_del(l, s->reply_wait_fd);
    int rc;
    if (s->raw_poll_paused) {
        rc = lc_loop_add(l, s->up_fd, LC_EV_WRITE, &s->up_tag);
        if (rc == 0)
            s->raw_poll_paused = 0;
    } else {
        rc = lc_loop_mod(l, s->up_fd, LC_EV_WRITE, &s->up_tag);
    }
    if (rc != 0)
        session_finish(l, s);
}

/* Gives back the memory of everything closed since the last sweep. Runs once a batch of events has
 * been dealt with, when nothing can still be holding a pointer. */
static void sessions_reap(void)
{
    for (unsigned i = 0; i < sessions_cap; i++) {
        session *s = sessions[i];
        if (s == NULL || !s->closing || s->close_by != 0)
            continue;
        sessions[i] = NULL;
        /* Wiped rather than merely freed: it has held the application traffic keys. */
        memset(s, 0, sizeof *s);
        free(s);
        session_count--;
    }
}

/* ---- the uplink, stage for stage as the reference's writers build it -------------------------------
 *
 * ⚠️ WHAT GOES ON THE WIRE TOWARDS THE NODE IS DECIDED BY FOUR WRITERS STACKED ON EACH OTHER, and this
 * file used to have one function standing in for all of them. From the top down:
 *
 *     VisionWriter.WriteMultiBuffer      frames each buffer         vendor/Xray-core/proxy/proxy.go:326
 *     BufferedWriter                     only for the first write   vendor/Xray-core/common/buf/writer.go:74
 *     BufferToBytesWriter                one Write per buffer        vendor/Xray-core/common/buf/writer.go:22
 *     tls.Conn.Write → writeRecordLocked one write(2) per record     vendor/utls/conn.go:982, :950
 *
 * and xudp's PacketWriter above the first of them on a datagram session. The shapes an observer can
 * count — how many records, how large, and in how many TCP writes — come out of how those stages hand
 * bytes to each other, so each stage is a function here with the name of what it stands for:
 * vision_mb_* for the first, bufw_* for the second, tls_write for the last two, conn_write for the
 * socket underneath. */

static int conn_write(session *s, const uint8_t *data, size_t len);
static int tls_write(session *s, const uint8_t *data, size_t len);

/* What Xray never puts in one padded frame, and where it cuts instead.
 *
 * ReshapeMultiBuffer (vendor/Xray-core/proxy/proxy.go:466-497) splits any buffer of buf.Size-21
 * bytes or more into two before padding touches it, and it does not split in the middle: it looks
 * for the LAST start of a TLS application-data record (0x17 0x03 0x03) and cuts there, falling back
 * to HALF THE BUFFER when that lands somewhere useless. The point is that each padded frame then
 * holds whole records, which is what an observer counting record sizes would see from a real TLS
 * connection.
 *
 * The numbers are buf.Size's, and buf.Size is 8192 (vendor/Xray-core/common/buf/buffer.go:13) — not
 * 2048, which is what stood here and what the constant below was derived from. Cutting at 2027
 * halved buffers the reference leaves whole, and worse: the guard `at > VISION_RESHAPE_AT` was then
 * true for almost every real buffer, so the search for the last record start was dead code and the
 * cut always landed on the fixed fallback, in the middle of a record. Both numbers are the
 * reference's now, and READ_CHUNK is 8192, so a buffer here is exactly the buffer there. */
#define VISION_RESHAPE_AT 8171u  /* buf.Size - 21, Xray's own bound */
#define VISION_RESHAPE_HALF 4096u /* buf.Size / 2, where Xray cuts when the search is useless */

static size_t reshape_at(const uint8_t *data, size_t len)
{
    if (len < VISION_RESHAPE_AT)
        return 0;

    size_t at = 0;
    for (size_t i = 0; i + 3u <= len; i++)
        if (data[i] == 0x17u && data[i + 1] == 0x03u && data[i + 2] == 0x03u)
            at = i;

    /* Xray's own guard: a cut before the header or past the bound is no cut at all, and then it
     * takes the middle — `index = buf.Size / 2` (vendor/Xray-core/proxy/proxy.go:481-483), a
     * constant there because every
     * buffer it sees is buf.Size long. */
    if (at < 21u || at > VISION_RESHAPE_AT)
        at = VISION_RESHAPE_HALF;
    return at;
}

/* ---- BufferedWriter: the one write that is assembled before it is sent ----
 *
 * The VLESS request header and whatever follows it in the same call are written into a BufferedWriter
 * that holds them until `SetBuffered(false)` (vendor/Xray-core/proxy/vless/outbound/outbound.go:
 * 310-344). It keeps ONE buffer of buf.Size and hands it to the connection each time it fills
 * (vendor/Xray-core/common/buf/writer.go:154-164), then whatever is left when buffering is switched
 * off (:202-211). So the first write of every connection reaches tls.Conn.Write as 8192-byte pieces
 * and a tail — the header and the first frame in the SAME piece, which is where the record boundary
 * falls, and where it fell for this client was after the header's frame had been sealed on its own.
 *
 * A stream's request is written inside one call — request_write assembles, flushes and is done — so
 * one instance serves every stream, on the same argument `scratch` makes. A datagram session's can
 * stop part way, and keeps its own with its queue: see struct udp_pend. */
static bufw request_buf;

static int bufw_write(session *s, bufw *w, const uint8_t *data, size_t len)
{
    while (len > 0) {
        size_t take = sizeof w->buf - w->len;
        if (take > len)
            take = len;
        memcpy(w->buf + w->len, data, take);
        w->len += take;
        data += take;
        len -= take;
        if (w->len == sizeof w->buf) {
            w->len = 0;
            if (tls_write(s, w->buf, sizeof w->buf) != 0)
                return -1;
        }
    }
    return 0;
}

static int bufw_flush(session *s, bufw *w)
{
    size_t n = w->len;
    w->len = 0;
    return n > 0 ? tls_write(s, w->buf, n) : 0;
}

/* Where one buffer of the Vision writer's output goes: into the BufferedWriter while the request is
 * being assembled, and after that straight to tls.Conn.Write — BufferToBytesWriter writes a MultiBuffer
 * one buffer per Write (net.Buffers.WriteTo on a writer that is not a buffersWriter,
 * vendor/Xray-core/common/buf/writer.go:48-63), so every frame is a Write of its own. */
static int up_out(session *s, bufw *bw, const uint8_t *data, size_t len)
{
    return bw != NULL ? bufw_write(s, bw, data, len) : tls_write(s, data, len);
}

/* ---- VisionWriter: one WriteMultiBuffer, over as many buffers as it was handed ----
 *
 * ONE WRITE, AND EVERYTHING THAT IS DECIDED ONCE FOR IT. This is the shape of
 * vendor/Xray-core/proxy/proxy.go:326-406, and three things about it were once decided per PIECE here
 * instead of per write:
 *
 *   - THE FILTER. `if NumberOfPacketToFilter > 0 { XtlsFilterTls(mb, ...) }`
 *     (vendor/Xray-core/proxy/proxy.go:357-359) runs on the ORIGINAL multi-buffer, before
 *     ReshapeMultiBuffer, and XtlsFilterTls spends one of the eight per buffer it is handed. Ours ran
 *     per piece, so a write that was cut in two spent TWO — and the budget is what decides where the
 *     CommandPaddingEnd that stops padding for the life of the connection lands.
 *
 *   - `isComplete`. Computed once over the whole MultiBuffer BEFORE the cut
 *     (vendor/Xray-core/proxy/proxy.go:365) and reused by every piece. Neither half of a single-record
 *     8 kB write can answer yes on its own, so asking each half made the End/Direct announcement never
 *     happen on exactly the write the reference makes it on.
 *
 *   - `longPadding`. Starts as IsTLS (vendor/Xray-core/proxy/proxy.go:367) — read AFTER the filter
 *     has run over this write — and is cleared by the first piece that matches, so the reference stops
 *     long-padding for the REST OF THIS WRITE.
 *
 * A write is begun, every buffer is scanned (the filter and isComplete, which the reference computes
 * over all of them before it frames any), and then every buffer is written — in three calls rather
 * than one because on the datagram path a write can stop between two buffers for want of queue room
 * and carry on when the socket drains, which is the event-loop form of the reference's goroutine
 * blocking inside Write. Nothing about what is written depends on where it stopped. */
static void vision_mb_begin(session *s, vision_mb *m)
{
    memset(m, 0, sizeof *m);
    /* `if *switchToDirectCopy { … w.Writer = buf.NewWriter(rawConn) }` comes first in the call
     * (vendor/Xray-core/proxy/proxy.go:338-355): a previous write turned the copier over, and this
     * one is the first to go raw. */
    m->raw = s->vision.direct_out;
    if (m->raw)
        s->raw_writer = 1;
    m->framing = s->vision.padding_out;
    m->filtering = s->vision.packets_to_filter > 0;
    m->cr_head = 5u;
}

static void vision_mb_scan(session *s, vision_mb *m, const uint8_t *data, size_t len)
{
    if (m->filtering && lc_vision_filter_piece(&s->vision, data, len))
        m->filtering = 0;

    m->pieces += len >= VISION_RESHAPE_AT ? 2u : 1u;

    /* IsCompleteRecord (vendor/Xray-core/proxy/proxy.go:410-457), byte for byte and across buffer
     * boundaries, because it runs over the concatenation: every record `17 03 03 len`, a length that
     * is not zero, and the last one ending exactly where the write does. An empty write is complete —
     * the loop never runs and both counters are where they started — which no path here produces and
     * the matched arm could not use anyway, since it wants six bytes. */
    for (size_t i = 0; i < len && !m->cr_bad;) {
        if (m->cr_head > 0u) {
            uint8_t b = data[i++];
            switch (m->cr_head) {
            case 5u: m->cr_bad = b != 0x17u; break;
            case 4u:
            case 3u: m->cr_bad = b != 0x03u; break;
            case 2u: m->cr_left = (size_t)b << 8; break;
            default: m->cr_left |= b; m->cr_bad = m->cr_left == 0u; break;
            }
            m->cr_head--;
        } else {
            size_t skip = m->cr_left < len - i ? m->cr_left : len - i;
            i += skip;
            m->cr_left -= skip;
            if (m->cr_left == 0u)
                m->cr_head = 5u;
        }
    }
}

static void vision_mb_ready(session *s, vision_mb *m)
{
    m->complete = !m->cr_bad && m->cr_head == 5u && m->cr_left == 0u;
    m->long_padding = s->vision.is_tls;
}

/* One piece of the write, after reshaping: the loop body. */
static int vision_mb_piece(session *s, vision_mb *m, bufw *bw, const uint8_t *data, size_t len)
{
    /* THE LOOP BODY OF vendor/Xray-core/proxy/proxy.go:368-396, arm for arm.
     *
     *     if IsTLS && b.Len() >= 6 && bytes.Equal(TlsApplicationDataStart, b.BytesTo(3)) && isComplete {
     *         if EnableXtls { *switchToDirectCopy = true }
     *         var command byte = CommandPaddingContinue
     *         if i == len(mb)-1 {
     *             command = CommandPaddingEnd
     *             if EnableXtls { command = CommandPaddingDirect }
     *         }
     *         mb[i] = XtlsPadding(b, command, ..., true, ...)
     *         *isPadding = false
     *         longPadding = false
     *         continue
     *     } else if !IsTLS12orAbove && NumberOfPacketToFilter <= 1 {
     *         *isPadding = false
     *         mb[i] = XtlsPadding(b, CommandPaddingEnd, ..., longPadding, ...)
     *         break
     *     }
     *     var command byte = CommandPaddingContinue
     *     if i == len(mb)-1 && !*isPadding {
     *         command = CommandPaddingEnd
     *         if EnableXtls { command = CommandPaddingDirect }
     *     }
     *     mb[i] = XtlsPadding(b, command, ..., longPadding, ...)
     *
     * The per-piece half of the match is only the length and the `17 03 03` prefix; `isComplete` is
     * the whole write's answer, computed before the cut.
     *
     * `*switchToDirectCopy = true` sits inside the match and NOT inside the `last` test: the reference
     * turns the copier over on any matching piece, and the pieces after it in this same write are
     * still framed because the writer is only replaced at the top of the NEXT call — `m->raw` is that
     * snapshot.
     *
     * The third arm is the fallthrough, and it exists for a piece that does NOT begin at a record
     * boundary but follows one that already cleared the flag. Without it the last piece of a cut write
     * carried Continue and the announcement was postponed to a later write.
     *
     * THE LONG-PADDING ARGUMENT IS NOT THE SAME IN ALL THREE ARMS: a literal `true` in the matched arm
     * and the running `longPadding` in the other two (vendor/Xray-core/proxy/proxy.go:380, 386, 396).
     * It only shows when one write has TWO matching pieces — the cut-in-two case — where the first
     * clears longPadding and the second is still padded long. */
    int last = m->piece + 1u == m->pieces;
    m->piece++;

    uint8_t command = LC_VISION_CONTINUE;
    int     matched = s->vision.is_tls && len >= 6u && data[0] == 0x17u && data[1] == 0x03u &&
                  data[2] == 0x03u && m->complete;
    int     long_this = m->long_padding;

    if (matched) {
        if (s->vision.enable_xtls && !s->vision.direct_out) {
            s->vision.direct_out = 1;
            if (log_per_connection())
                note("direct copy engaged upstream for %s:%u", s->target_host, s->target_port);
        }
        if (last)
            command = s->vision.enable_xtls ? LC_VISION_DIRECT : LC_VISION_END;
        long_this = 1;
        s->vision.padding_out = 0;
        m->long_padding = 0;
    } else if (!s->vision.is_tls12_or_above && s->vision.packets_to_filter <= 1) {
        /* The filter has looked at everything it is going to look at and has not found TLS. Padding
         * every write for the life of the connection after that buys nothing and is not what an Xray
         * client does — it says so once and stops, one packet before the filter formally runs out,
         * for the sake of receivers that count. `break`, so nothing after this piece is framed. */
        command = LC_VISION_END;
        s->vision.padding_out = 0;
        m->stop = 1;
    } else if (last && !s->vision.padding_out) {
        command = s->vision.enable_xtls ? LC_VISION_DIRECT : LC_VISION_END;
    }

    size_t framed_len = 0;
    stats.vision_frames++;
    if (lc_vision_pad(&s->vision, command, long_this, data, len, scratch.framed,
                      sizeof scratch.framed, &framed_len) != 0)
        return -1;
    return up_out(s, bw, scratch.framed, framed_len);
}

/* One buffer of the write. */
static int vision_mb_write(session *s, vision_mb *m, bufw *bw, const uint8_t *data, size_t len)
{
    /* Raw: the node was told the record layer stops here, and from this point the direction costs no
     * framing and no second encryption. What goes out is the inner connection's own TLS, which is why
     * this is safe as well as fast.
     *
     * ONE write(2) PER BUFFER, which is what the reference's raw writer does for a MultiBuffer of one
     * — WriteAllBytes on the socket (vendor/Xray-core/common/buf/writer.go:30-32). A longer one is a
     * single writev there, and stream_pump makes it before this is reached. ⚠️ "None reaches this
     * branch, because only the datagram path hands over more than one buffer" stood here until
     * 2026-09-27, and the stream's readv form hands over up to eight.
     *
     * Counted only once the socket or the queue has taken it, which is NOT how bytes_out is counted.
     * The two sit on different lines and answer different questions: bytes_out is beside a record
     * count and describes work this process did, while this one is beside direct_bytes on the
     * `direct` line, and direct_bytes is what splice actually moved. */
    if (m->raw) {
        int rc = conn_write(s, data, len);
        if (rc == 0)
            stats.direct_up_bytes += (uint64_t)len;
        return rc;
    }

    /* Framing over but the record layer still on — or framing stopped by an earlier piece of this
     * write, whose `break` (vendor/Xray-core/proxy/proxy.go:387) leaves the remaining buffers in mb
     * exactly as they were, sealed by the record layer and padded by nothing. Reproduced rather than
     * tidied away: it is a frame sequence an observer can see. */
    if (!m->framing || m->stop)
        return up_out(s, bw, data, len);

    size_t at = reshape_at(data, len);
    if (at == 0)
        return vision_mb_piece(s, m, bw, data, len);
    if (vision_mb_piece(s, m, bw, data, at) != 0)
        return -1;
    if (m->stop)
        return up_out(s, bw, data + at, len - at);
    return vision_mb_piece(s, m, bw, data + at, len - at);
}

/* ---- what the uplink reads, which is not a pipe --------------------------------------------------
 *
 * ⚠️ THE READER THE REFERENCE WRITES FROM IS THE CLIENT'S OWN SOCKET, and a first version of this
 * block modelled a pipe between the two that the transparent path does not have. Xray's tproxy inbound
 * is dokodemo-door, and it hands its reader straight to `dispatcher.DispatchLink`
 * (vendor/Xray-core/proxy/dokodemo/dokodemo.go:152-199), which wraps it once — in the
 * TimeoutWrapperReader request_write describes — and gives it to the outbound
 * (vendor/Xray-core/app/dispatcher/default.go:324-344). No pipe, no copy loop, no per-architecture
 * buffer limit: whenever the VLESS outbound asks for more, what it gets is one read of that reader.
 *
 * Measured, because the pipe model was a reading and this is too: the reference client on the local
 * stand, given six datagrams in a burst while its tunnel was being built, sent all six in its first
 * write — 1208 + 302 bytes, two records — built both with its own amd64 buffer limit and with the
 * mipsle one pinned. The pipe model predicted [first], [second], [the rest].
 *
 * So there are two readers, one per plane of traffic, and each is reproduced as what it is. */

/* What the LAN sent on an open stream, as ONE buffer: the reader's first form, below. */
static int push_up_reshaped(session *s, const uint8_t *data, size_t len)
{
    if (!s->use_vision)
        return tls_write(s, data, len);

    vision_mb m;
    vision_mb_begin(s, &m);
    vision_mb_scan(s, &m, data, len);
    vision_mb_ready(s, &m);
    return vision_mb_write(s, &m, NULL, data, len);
}

/* ---- the stream: ReadVReader ----
 *
 * For a TCP connection `buf.NewReader(conn)` is a ReadVReader whenever the connection can hand over its
 * descriptor, which the accepted *net.TCPConn can (vendor/Xray-core/common/buf/io.go:113-146), and readv
 * is on by default on Linux (vendor/Xray-core/common/buf/readv_reader.go:153-163). It does not read one
 * buffer at a time. It offers `current` buffers of buf.Size to one readv and adapts the number:
 *
 *     if r.alloc.Current() == 1 {
 *         b, err := ReadBuffer(r.Reader)
 *         if b.IsFull() { r.alloc.Adjust(1) }
 *         return MultiBuffer{b}, err
 *     }
 *     mb, err := r.readMulti()                  // readv into Current() buffers
 *     r.alloc.Adjust(uint32(len(mb)))
 *
 *     func (s *allocStrategy) Adjust(n uint32) {
 *         if n >= s.current { s.current *= 2 } else { s.current = n }
 *         if s.current > 8 { s.current = 8 }
 *         if s.current == 0 { s.current = 1 }
 *     }
 *                    (vendor/Xray-core/common/buf/readv_reader.go:15-37, :75-146)
 *
 * So a connection sending faster than it is read hands the outbound two, four, then eight buffers per
 * write, and VisionWriter decides isComplete, the last piece's command and the filter's count over all
 * of them together; the raw writer, once direct copy is on, writes them with one writev.
 *
 * The first form is the read the event loop already makes — one read of READ_CHUNK — with the Adjust
 * after it. The second takes what readv would have taken WITHOUT holding it: FIONREAD says how much the
 * kernel has, which is what readv would return, capped at `current` buffers; MSG_PEEK shows those bytes
 * to the filter and IsCompleteRecord, which the reference computes over the whole write before framing
 * any of it; and then each buffer is read as it is written, which can stop for want of queue room and
 * carry on when the socket drains. The bytes are the same bytes, in the same buffers — the kernel's
 * receive queue only grows until it is read — and no session holds 64 KB to do it. */

static unsigned rv_current(const session *s)
{
    return s->rv_alloc > 0u ? s->rv_alloc : 1u;
}

static void rv_adjust(session *s, unsigned n)
{
    unsigned cur = rv_current(s);
    cur = n >= cur ? cur * 2u : n;
    if (cur > 8u)
        cur = 8u;
    if (cur == 0u)
        cur = 1u;
    s->rv_alloc = cur;
}

/* Xray ReadVReader.ReadMultiBuffer's first form calls ReadBuffer on the TCP
 * reader. Go 1.27.1 internal/poll/fd_unix.go::FD.Read retries EINTR inside
 * ignoringEINTRIO. Retry here before classifying epoll's simultaneous error:
 * an interrupted read has not consumed the bytes queued before a TCP reset. */
static ssize_t stream_read_first(session *s, uint8_t *buf)
{
    ssize_t got;
    do {
        stats.reads_lan++;
        got = read(s->lan_fd, buf, READ_CHUNK);
    } while (got < 0 && errno == EINTR);
    return got;
}

/* Where a multi-buffer write's bytes are shown to the filter. Only between peeking and scanning, like
 * scratch; wiped after, because it is the user's traffic in a buffer every session shares. */
static uint8_t stream_peek[8u * READ_CHUNK];

/* EINTR has not consumed socket bytes. Keep this MultiBuffer and retry the
 * interrupted operation, as Go's FD.Read/Writev do (Go 1.27.1 internal/poll/
 * fd_unix.go::Read, writev.go::Writev). Xray ReadVReader.readMulti also keeps
 * its allocation when its read callback reports no result. EAGAIN, short
 * reads and permanent errors retain their existing handling below. */
static int stream_pump(session *s)
{
    /* RAW AND MORE THAN ONE BUFFER: ONE writev. Once the copier has turned over, VisionWriter's writer
     * is buf.NewWriter on the raw socket, whose MultiBuffer of more than one goes out through
     * net.Buffers.WriteTo — a single writev, repeated only for what the socket did not take
     * (vendor/Xray-core/proxy/proxy.go:348-349, vendor/Xray-core/common/buf/writer.go:31-67). Shown
     * with MSG_PEEK, written in one call, and only what went out — or what the queue then takes — is
     * read off the client's socket, so a socket that takes part leaves the rest where it lies.
     * ⚠️ UNTIL 2026-09-27 one write per buffer: eight calls where the reference makes one. */
    if (s->use_vision && s->up_mb.raw && s->up_n > 1u && s->up_done == 0u) {
        while (s->up_left > 0u) {
            if (q_pending(&s->to_up) > 0u)
                return 0;
            ssize_t seen;
            do { seen = recv(s->lan_fd, stream_peek, s->up_left, MSG_PEEK); }
            while (seen < 0 && errno == EINTR);
            if (seen != (ssize_t)s->up_left)
                return -1;
            ssize_t w;
            do { w = write(s->up_fd, stream_peek, s->up_left); }
            while (w < 0 && errno == EINTR);
            if (w == 0 || (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                lc_wipe(stream_peek, s->up_left);
                return -1;
            }
            size_t went = w > 0 ? (size_t)w : 0u;
            size_t rest = s->up_left - went;
            size_t queued = rest < q_room(&s->to_up) ? rest : q_room(&s->to_up);
            if (queued > 0u && q_push(&s->to_up, stream_peek + went, queued) != 0) {
                lc_wipe(stream_peek, s->up_left);
                return -1;
            }
            lc_wipe(stream_peek, s->up_left);
            size_t done = went + queued;
            if (done > 0u) {
                /* Read off what has gone or is queued — the same bytes, still in the kernel. */
                uint8_t sink[READ_CHUNK];
                for (size_t off = 0; off < done;) {
                    size_t  step = done - off < sizeof sink ? done - off : sizeof sink;
                    ssize_t r;
                    do { r = read(s->lan_fd, sink, step); } while (r < 0 && errno == EINTR);
                    if (r != (ssize_t)step)
                        return -1;
                    off += step;
                }
                lc_wipe(sink, sizeof sink);
                stats.reads_lan++;
                stats.direct_up_bytes += (uint64_t)done;
                s->up_left -= done;
            }
            if (s->up_left > 0u && q_pending(&s->to_up) == 0u)
                return 0; /* nothing went and nothing fits: the socket's drain brings us back */
        }
        s->up_done = s->up_n;
        s->up_n = 0u;
        return 0;
    }

    while (s->up_done < s->up_n) {
        if (q_room(&s->to_up) < UP_WORST_PER_READ)
            return 0;
        uint8_t buf[READ_CHUNK];
        size_t  take = s->up_left < READ_CHUNK ? s->up_left : READ_CHUNK;
        stats.reads_lan++;
        ssize_t got;
        do { got = read(s->lan_fd, buf, take); } while (got < 0 && errno == EINTR);
        if (got != (ssize_t)take)
            return -1;
        int rc = s->use_vision ? vision_mb_write(s, &s->up_mb, NULL, buf, take)
                               : tls_write(s, buf, take);
        if (rc != 0)
            return -1;
        s->up_left -= take;
        s->up_done++;
    }
    s->up_n = 0u;
    return 0;
}

/* The second form, for a reader whose `current` is above one. Returns 1 when it took a write — and
 * wrote it as far as the queue allows — 0 when the kernel had nothing after all, STREAM_EOF at the end
 * of the stream, -1 on failure. */
#define STREAM_EOF 2

static int stream_take(session *s)
{
    int avail = 0;
    int available;
    do { available = ioctl(s->lan_fd, FIONREAD, &avail); }
    while (available < 0 && errno == EINTR);
    if (available != 0)
        return -1;
    if (avail <= 0) {
        /* Nothing queued, and readable: the end of the stream or an error, which readv would return
         * as 0 or -1. Asked without consuming anything, in case a byte arrived in between. */
        uint8_t one;
        ssize_t r;
        do { r = recv(s->lan_fd, &one, 1, MSG_PEEK); } while (r < 0 && errno == EINTR);
        if (r == 0)
            return STREAM_EOF;
        if (r < 0)
            return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
        do { available = ioctl(s->lan_fd, FIONREAD, &avail); }
        while (available < 0 && errno == EINTR);
        if (available != 0)
            return -1;
        if (avail <= 0)
            return 0;
    }

    size_t cap = (size_t)rv_current(s) * READ_CHUNK;
    size_t n = (size_t)avail < cap ? (size_t)avail : cap;
    unsigned bufs = (unsigned)((n + READ_CHUNK - 1u) / READ_CHUNK);
    rv_adjust(s, bufs);

    s->up_n = bufs;
    s->up_done = 0u;
    s->up_left = n;
    act_update(s); /* the copy's onData, once per MultiBuffer */
    if (s->use_vision) {
        vision_mb_begin(s, &s->up_mb);
        if (s->up_mb.framing || s->up_mb.filtering) {
            ssize_t seen;
            do { seen = recv(s->lan_fd, stream_peek, n, MSG_PEEK); }
            while (seen < 0 && errno == EINTR);
            if (seen != (ssize_t)n)
                return -1;
            for (size_t off = 0; off < n; off += READ_CHUNK)
                vision_mb_scan(s, &s->up_mb, stream_peek + off,
                               n - off < READ_CHUNK ? n - off : READ_CHUNK);
            lc_wipe(stream_peek, n);
        }
        vision_mb_ready(s, &s->up_mb);
    }
    return stream_pump(s) != 0 ? -1 : 1;
}

/* ---- the datagram uplink ---------------------------------------------------------------------------
 *
 * ⚠️ DATAGRAMS WENT UP WITHOUT VISION, AND EACH IN A RECORD OF ITS OWN, WHICH NO XRAY CLIENT SENDS.
 *
 * With the Vision flow the reference rewrites a UDP request into Mux, and then `EncodeBodyAddons`
 * returns a VisionWriter for it — the Mux command is not the UDP command it tests for — and xudp's
 * PacketWriter is stacked ON TOP of that (vendor/Xray-core/proxy/vless/outbound/outbound.go:304, :318-320,
 * vendor/Xray-core/proxy/vless/encoding/addons.go:66-74). So every xudp frame is a buffer handed to
 * VisionWriter: filtered, framed with padding until the filter gives up, and for the first one of a
 * connection, preceded by the UUID. This client sealed the frame straight into a record.
 *
 * And the datagrams that arrived while the tunnel was being built go out WITH the request header, in
 * its one buffered write, where this sent the header as a record and each datagram as the next.
 *
 * WHICH DATAGRAMS TRAVEL TOGETHER is the reader's answer. The UDP inbound puts every datagram into a
 * 16 KB pipe with DiscardOverflow (vendor/Xray-core/app/proxyman/inbound/worker.go:289), and that pipe
 * IS the reader dokodemo hands over: `buf.NewPacketReader(conn)` returns the udpConn itself
 * (vendor/Xray-core/common/buf/io.go:148-151), whose ReadMultiBuffer takes everything the pipe holds
 * (vendor/Xray-core/app/proxyman/inbound/worker.go:195-207, vendor/Xray-core/transport/pipe/impl.go:
 * 78-89). So each write carries every datagram that arrived since the last one was taken: one at a
 * time while the writer keeps up, all of them together when it has been busy — the handshake, or a
 * socket that stopped taking bytes. pend_q is that pipe; a write takes all of it; what arrives while
 * the write is under way waits for the next. */

/* One entry of the pending queue, read back. Returns its size in the queue, or 0 for a queue that ends
 * inside one — which pend_put never writes. */
static size_t pend_entry(const struct udp_pend *q, size_t off, char *host, uint16_t *port,
                         const uint8_t **data, size_t *len)
{
    const uint8_t *p = q->buf + off;
    const uint8_t *end = q->buf + q->len;
    if (p >= end)
        return 0;
    size_t host_len = *p++;
    if ((size_t)(end - p) < host_len + 4u)
        return 0;
    memcpy(host, p, host_len);
    host[host_len] = '\0';
    p += host_len;
    *port = (uint16_t)((uint16_t)p[0] << 8 | p[1]);
    p += 2;
    *len = (size_t)p[0] << 8 | p[1];
    p += 2;
    if ((size_t)(end - p) < *len)
        return 0;
    *data = p;
    return (size_t)(p - (q->buf + off)) + *len;
}

/* Where one xudp frame is built. Not `scratch.framed`: that is where the Vision frame AROUND this one
 * is written, from these bytes. Alive only between building a frame and handing it on, like scratch. */
static uint8_t udp_frame[READ_CHUNK];

/* The frame the reference's PacketWriter makes for entry `off` of the queue. `first` is its
 * `w.Dest.Network == net.Network_UDP` — New for the first frame of the connection, Keep after
 * (vendor/Xray-core/common/xudp/xudp.go:95-136). */
static int udp_frame_at(session *s, size_t off, int first, size_t *frame_len, size_t *entry_len,
                        size_t *payload_len)
{
    char           host[256];
    uint16_t       port = 0;
    const uint8_t *data = NULL;
    size_t         e = pend_entry(s->pend_q, off, host, &port, &data, payload_len);
    if (e == 0u)
        return -1;
    *entry_len = e;
    /* Command 0x02: the length and the bytes, MultiLengthPacketWriter's form
     * (vendor/Xray-core/proxy/vless/encoding/addons.go:96-122) — no address, since the header named
     * the one destination the whole connection has. */
    if (s->plain_udp) {
        if (*payload_len + 2u > sizeof udp_frame)
            return -1;
        udp_frame[0] = (uint8_t)(*payload_len >> 8);
        udp_frame[1] = (uint8_t)*payload_len;
        memcpy(udp_frame + 2, data, *payload_len);
        *frame_len = *payload_len + 2u;
        return 0;
    }
    if (s->udp_unaddressed)
        return lc_xudp_wrap_unaddressed(first, host, port, data, *payload_len, udp_frame,
                                        sizeof udp_frame, frame_len);
    return lc_xudp_wrap(first, host, port, s->global_id, data, *payload_len, udp_frame,
                        sizeof udp_frame, frame_len);
}

static int request_header(session *s, bufw *bw);

/* Takes everything pend_q holds as one write and writes it, for as long as the queue towards the node
 * has room for the worst a buffer can become; comes back to it when the socket drains. While the
 * request is still due, the write is the request's: the header goes into the session's buffered write
 * first, every datagram after it, and the whole flushes at the end — SetBuffered(false). */
static int udp_pump(session *s)
{
    for (;;) {
        if (s->up_n == 0u) {
            if (s->pend_q->count == 0u)
                return 0;
            s->up_n = s->pend_q->count;
            s->up_done = 0u;
            s->up_at = 0u;
            s->up_end = s->pend_q->len;
            /* The inbound's ReadMultiBuffer is activity to its checker; the copy's onData is activity
             * to the timer, but the request's first write is not a copy. */
            udp_seen(s);
            if (!s->request_due)
                act_update(s);
            if (s->request_due) {
                s->pend_q->request.len = 0;
                if (request_header(s, &s->pend_q->request) != 0)
                    return -1;
            }
            if (s->use_vision) {
                vision_mb_begin(s, &s->up_mb);
                size_t off = 0;
                for (unsigned i = 0; i < s->up_n; i++) {
                    size_t flen = 0, elen = 0, plen = 0;
                    if (udp_frame_at(s, off, !s->xudp_started && i == 0u, &flen, &elen, &plen) != 0)
                        return -1;
                    vision_mb_scan(s, &s->up_mb, udp_frame, flen);
                    off += elen;
                }
                vision_mb_ready(s, &s->up_mb);
            }
        }

        /* Room for the worst one buffer can become. A frame into the buffered write hands on at most
         * one full buf.Size of it, and the flush at the end at most one more, so the same bound holds
         * for each step of the request as for a write of its own. */
        bufw *bw = s->request_due ? &s->pend_q->request : NULL;
        while (s->up_done < s->up_n) {
            if (q_room(&s->to_up) < UP_WORST_PER_READ)
                return 0;
            size_t flen = 0, elen = 0, plen = 0;
            if (udp_frame_at(s, s->up_at, !s->xudp_started, &flen, &elen, &plen) != 0)
                return -1;
            s->xudp_started = 1;
            int rc = s->use_vision ? vision_mb_write(s, &s->up_mb, bw, udp_frame, flen)
                                   : up_out(s, bw, udp_frame, flen);
            if (rc != 0)
                return -1;
            /* Counted here rather than where the datagram arrived, because between those two points
             * sit an oversize refusal, a per-peer limit and a queue that drops when it is full.
             * Counting at the listener answers "what turned up"; the ratio this feeds needs "what was
             * carried". */
            stats.udp_bytes_up += (uint64_t)plen;
            s->up_at += elen;
            s->up_done++;
        }

        if (bw != NULL) {
            if (q_room(&s->to_up) < UP_WORST_PER_READ)
                return 0;
            if (bufw_flush(s, bw) != 0)
                return -1;
            s->request_due = 0;
        }

        memmove(s->pend_q->buf, s->pend_q->buf + s->up_end, s->pend_q->len - s->up_end);
        s->pend_q->len -= s->up_end;
        s->pend_q->count -= s->up_n;
        s->up_n = 0u;
        s->up_end = 0u;
    }
}

/* ONE conn.Write, WHICH IS ONE write(2) — what every record the reference seals becomes.
 *
 * writeRecordLocked hands each record to c.write as soon as it is sealed, and once the handshake has
 * stopped buffering c.write is `c.conn.Write(data)` straight onto the socket
 * (vendor/utls/conn.go:950-959, :1009-1050). With TCP_NODELAY on — Go sets it on every TCP
 * connection, and net/sock.c sets it on ours — a write leaves as its own segment whenever the
 * window allows. This client queued a
 * whole read's records back to back and flushed them in one write, so the kernel cut them at the MSS
 * instead: the first two records of a connection, 1208 bytes each on the wire in the reference, left
 * as 1448 + 968. A segment size is readable by anything on the path, and no decryption is involved.
 *
 * Straight to the socket when nothing is waiting ahead of it, so the boundary is the reference's.
 * Behind whatever is waiting, into the queue, when something is: the kernel is then already holding
 * unsent bytes and packs what follows by the window, which is also what becomes of the reference's
 * Write while it blocks. */
static int conn_write(session *s, const uint8_t *data, size_t len)
{
    size_t off = 0;
    if (q_pending(&s->to_up) == 0) {
        while (off < len) {
            ssize_t n = write(s->up_fd, data + off, len - off);
            if (n > 0) {
                off += (size_t)n;
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            return -1;
        }
    }
    return off == len ? 0 : q_push(&s->to_up, data + off, len - off);
}

/* ONE tls.Conn.Write: the payload cut into records the way Go cuts it, each written as it is sealed.
 *
 * THE RECORD SIZE IS NOT OURS TO CHOOSE, AND IT WAS. This used to seal whatever it was handed into ONE
 * record, so an 8192-byte read from the LAN became an 8192-byte record. Go never emits that shape early
 * in a connection. Its writer caps each application-data record at a size that grows in arithmetic
 * progression:
 *
 *     if c.bytesSent >= recordSizeBoostThreshold { return maxPlaintext }
 *     payloadBytes := tcpMSSEstimate - recordHeaderLen - c.out.explicitNonceLen()
 *     payloadBytes -= ciph.Overhead()
 *     if c.vers == VersionTLS13 { payloadBytes-- }   // encrypted ContentType
 *     pkt := c.packetsSent; c.packetsSent++
 *     if pkt > 1000 { return maxPlaintext }
 *     n := payloadBytes * int(pkt+1); if n > maxPlaintext { n = maxPlaintext }
 *                                        (vendor/utls/conn.go:903-948)
 *
 * with tcpMSSEstimate = 1208 and recordSizeBoostThreshold = 128*1024 (:879-884). For TLS 1.3 the
 * explicit nonce is zero and both AEADs overhead 16, so payloadBytes is 1208-5-0-16-1 = 1186 and the
 * caps run 1186, 2372, 3558, 4744 ... to 16384.
 *
 * ⚠️ `bytesSent` IS EVERYTHING WRITTEN TO THE SOCKET, and this counted plaintext from the first
 * application record. c.write and c.flush add what the connection accepted, whatever it was
 * (vendor/utls/conn.go:957, :967): the ClientHello, the ChangeCipherSpec and Finished, and every
 * record's header and tag. So the boost to full-size records comes a ClientHello and some twenty bytes
 * a record EARLIER in the reference than it did here — a kilobyte and a half of hybrid key share, and
 * then a record-size schedule shifted by it for the rest of the first 128 KiB. The handshake's bytes
 * are added where advance_handshake writes them, and each record's whole wire length here.
 *
 * A zero-length Write sends nothing: the loop in writeRecordLocked is `for len(data) > 0`. The comment
 * that stood here said Go "emits one for an empty write", and this function kept a do-while to match
 * a record the reference never makes.
 *
 * The counters are per session because a Go tls.Conn is per connection, and this client makes one
 * REALITY connection per session; dial_node starts them again for every attempt. */
static int tls_write_progress(session *s, const uint8_t *payload, size_t len,
                              size_t *offset, int suspend_on_queue)
{
    size_t off = *offset;
    while (off < len) {
        if (suspend_on_queue && q_pending(&s->to_up) != 0)
            break;
        size_t cap = LC_REC_MAX_PLAINTEXT;
        if (s->tls_bytes_sent < LC_RECORD_BOOST_THRESHOLD) {
            uint64_t pkt = s->tls_records_sent++;
            if (pkt <= 1000u) {
                uint64_t n = (uint64_t)LC_RECORD_PAYLOAD_STEP * (pkt + 1u);
                cap = n > LC_REC_MAX_PLAINTEXT ? LC_REC_MAX_PLAINTEXT : (size_t)n;
            }
        }

        size_t take = len - off;
        if (take > cap)
            take = cap;

        size_t rec_len = 0;
        if (lc_record_protect(&s->cl.wr, LC_REC_APPLICATION_DATA, payload + off, take, 0,
                              scratch.rec, sizeof scratch.rec, &rec_len) != 0)
            return -1;
        stats.rec_out++;
        stats.bytes_out += take;
        s->tls_bytes_sent += rec_len;
        if (conn_write(s, scratch.rec, rec_len) != 0)
            return -1;
        off += take;
        *offset = off;
    }
    return 0;
}

static int tls_write(session *s, const uint8_t *payload, size_t len)
{
    size_t offset = 0;
    return tls_write_progress(s, payload, len, &offset, 0);
}

#if LC_SPIDER_PROFILE
static uint64_t spider_profile_now(void)
{
    struct timespec t;
    (void)clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

static void spider_profile_report(session *s)
{
    if (s->spider_profile_reported || s->spider_profile_base == 0u)
        return;
    if (!atomic_load_explicit(&s->spider_profile_entry_ready, memory_order_acquire) ||
        !atomic_load_explicit(&s->spider_profile_request_entry_ready, memory_order_acquire))
        return;
    s->spider_profile_reported = 1;
    uint64_t base = s->spider_profile_base;
    fprintf(stderr, "SPIDER_PROFILE fd=%d base=%llu logged=%llu allocated=%llu transferred=%llu "
                    "handoff=%llu fetch=%llu create=%llu created=%llu "
                    "entry=%llu request_entry=%llu wake=%llu opening=%llu request=%llu\n", s->up_fd,
            (unsigned long long)base,
            (unsigned long long)(s->spider_profile_logged - base),
            (unsigned long long)(s->spider_profile_allocated - base),
            (unsigned long long)(s->spider_profile_transferred - base),
            (unsigned long long)(s->spider_profile_handoff - base),
            (unsigned long long)(s->spider_profile_fetch - base),
            (unsigned long long)(s->spider_profile_create - base),
            (unsigned long long)(s->spider_profile_created - base),
            (unsigned long long)(s->spider_profile_entry - base),
            (unsigned long long)(s->spider_profile_request_entry - base),
            (unsigned long long)(s->spider_profile_wake == 0u ? 0u : s->spider_profile_wake - base),
            (unsigned long long)(s->spider_profile_opening - base),
            (unsigned long long)(spider_profile_now() - base));
    unsigned count = atomic_load_explicit(&s->spider_profile_count, memory_order_acquire);
    for (unsigned i = 0; i < count; i++)
        fprintf(stderr, "SPIDER_STEP base=%llu i=%u wait_begin=%llu wait_end=%llu "
                        "begin=%llu end=%llu rc=%d\n", (unsigned long long)base, i,
                (unsigned long long)(s->spider_profile_steps[i].wait_begin - base),
                (unsigned long long)(s->spider_profile_steps[i].wait_end - base),
                (unsigned long long)(s->spider_profile_steps[i].step_begin - base),
                (unsigned long long)(s->spider_profile_steps[i].step_end - base),
                s->spider_profile_steps[i].result);
}
#endif

static void spider_worker_notify(session *s)
{
    uint64_t one = 1u;
    while (write(s->spider_wake_fd, &one, sizeof one) < 0 && errno == EINTR) {
    }
}

static void *spider_worker_main(void *arg)
{
    session *s = arg;
    uint64_t generation = 0;
#if LC_SPIDER_PROFILE
    s->spider_profile_entry = spider_profile_now();
    atomic_store_explicit(&s->spider_profile_entry_ready, 1u, memory_order_release);
#endif
    for (;;) {
#if LC_SPIDER_PROFILE
        uint64_t wait_begin = spider_profile_now();
#endif
        int waited = lc_spider_fetch_wait(s->fetch, &generation);
#if LC_SPIDER_PROFILE
        uint64_t wait_end = spider_profile_now();
#endif
        if (waited <= 0) {
            if (waited < 0)
                atomic_store_explicit(&s->spider_worker_result, -1, memory_order_release);
            atomic_store_explicit(&s->spider_worker_done, 1, memory_order_release);
            spider_worker_notify(s);
            return NULL;
        }
        int rc;
        do {
#if LC_SPIDER_PROFILE
            uint64_t step_begin = spider_profile_now();
#endif
            rc = lc_spider_fetch_step(s->fetch, lc_now_ms());
#if LC_SPIDER_PROFILE
            unsigned i = atomic_load_explicit(&s->spider_profile_count, memory_order_relaxed);
            if (i < 16u) {
                s->spider_profile_steps[i].wait_begin = wait_begin;
                s->spider_profile_steps[i].wait_end = wait_end;
                s->spider_profile_steps[i].step_begin = step_begin;
                s->spider_profile_steps[i].step_end = spider_profile_now();
                s->spider_profile_steps[i].result = rc;
                atomic_store_explicit(&s->spider_profile_count, i + 1u, memory_order_release);
            }
#endif
        } while (rc == 1);
        /* DIVERGES: O5. Publish the result with the batch's wake, not each
         * private runnable phase. The TLS owner only consumes terminal errors;
         * completion and eventfd publication still follow this release store. */
        atomic_store_explicit(&s->spider_worker_result, rc, memory_order_release);
        /* Internal continuations need no socket turn. Publish one wake when this
         * task actually waits (including its own Write), finishes or fails.
         * DIVERGES: O5. No timer, polling turn or Write completion is inserted. */
        if (rc < 0)
            atomic_store_explicit(&s->spider_worker_done, 1, memory_order_release);
        spider_worker_notify(s);
        if (rc < 0)
            return NULL;
    }
}

/* doRequest shares the protocol lock, not Do's private-work lock or its
 * continuation loop. TLS/socket access remains exclusively on the event loop. */
static void *spider_request_worker_main(void *arg)
{
    session *s = arg;
#if LC_SPIDER_PROFILE
    s->spider_profile_request_entry = spider_profile_now();
    atomic_store_explicit(&s->spider_profile_request_entry_ready, 1u, memory_order_release);
#endif
    for (;;) {
        int waited = lc_spider_fetch_request_wait(s->fetch);
        if (waited == 0) {
            atomic_store_explicit(&s->spider_request_done, 1, memory_order_release);
            spider_worker_notify(s);
            return NULL;
        }
        if (waited < 0) {
            (void)lc_spider_fetch_request_step(s->fetch); /* Terminal final werr checks. */
            atomic_store_explicit(&s->spider_request_result, -1, memory_order_release);
            atomic_store_explicit(&s->spider_request_done, 1, memory_order_release);
            spider_worker_notify(s);
            return NULL;
        }
        int rc;
        do {
            rc = lc_spider_fetch_request_step(s->fetch);
        } while (rc == 1);
        atomic_store_explicit(&s->spider_request_result, rc, memory_order_release);
        /* As with Do, drain runnable protocol phases before waking the TLS owner. */
        if (rc < 0)
            atomic_store_explicit(&s->spider_request_done, 1, memory_order_release);
        spider_worker_notify(s);
        if (rc < 0)
            return NULL;
    }
}

static int spider_tasks_prepare(session *s)
{
    if (lc_spider_fetch_write_barrier(s->fetch) != 0 ||
        lc_spider_fetch_request_tasks(s->fetch) != 0) {
        note("spider startup fd=%d: cannot prepare HTTP/2 task ownership", s->up_fd);
        return -1;
    }
    return 0;
}

/* Modes are configured before the opening Write; starting workers must not
 * reset them while that Write is retained behind socket backpressure. */
static int spider_worker_start(lc_loop *l, session *s)
{
    s->spider_wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (s->spider_wake_fd < 0) {
        note("spider startup fd=%d: eventfd failed: %s", s->up_fd, strerror(errno));
        return -1;
    }
    if (lc_loop_add(l, s->spider_wake_fd, LC_EV_READ, &s->spider_tag) != 0) {
        note("spider startup fd=%d: wake registration failed: %s", s->up_fd, strerror(errno));
        return -1;
    }
    atomic_store_explicit(&s->spider_worker_result, 0, memory_order_relaxed);
    atomic_store_explicit(&s->spider_request_result, 0, memory_order_relaxed);
    atomic_store_explicit(&s->spider_worker_done, 0, memory_order_relaxed);
    atomic_store_explicit(&s->spider_request_done, 0, memory_order_relaxed);
#if LC_SPIDER_PROFILE
    s->spider_profile_create = spider_profile_now();
#endif
    /* DIVERGES: O6. Start the producer before its idle request executor, so
     * initial RoundTrip admission can overlap the second native creation.
     * Go already runs Do when internalRoundTrip starts cs.doRequest
     * (vendor/x-net/http2/transport.go:976-994). Readiness is a predicate:
     * the later request task must observe fields queued before it existed. */
    int error = pthread_create(&s->spider_worker, NULL, spider_worker_main, s);
    if (error != 0) {
        note("spider startup fd=%d: Do worker creation failed (%d: %s)",
             s->up_fd, error, strerror(error));
        return -1;
    }
    s->spider_worker_on = 1;
    error = pthread_create(&s->spider_request_worker, NULL, spider_request_worker_main, s);
    if (error != 0) {
        note("spider startup fd=%d: request worker creation failed (%d: %s)",
             s->up_fd, error, strerror(error));
        spider_worker_stop(s); /* Roll back the first task before releasing its session. */
        return -1;
    }
#if LC_SPIDER_PROFILE
    s->spider_profile_created = spider_profile_now();
#endif
    s->spider_request_worker_on = 1;
    return 0;
}

/* What the spider's fetch has to write, each a Write of its own on the TLS connection — one flush
 * of x/net's buffered writer, which is what the reference's records are cut along. */
static int spider_write_complete(session *s)
{
    if (!s->spider_write_pending || q_pending(&s->to_up) != 0)
        return 0;
    /* Keep the logical Write (and TLS write lock) across socket backpressure. Only one
     * record can be queued: the next record is sealed after that queue reaches the socket. */
    if (tls_write_progress(s, s->spider_write, s->spider_write_len,
                           &s->spider_write_off, 1) != 0) {
        (void)lc_spider_fetch_write_complete(s->fetch, 0);
        return -1;
    }
    if (q_pending(&s->to_up) != 0)
        return 0;
    free(s->spider_write);
    s->spider_write = NULL;
    s->spider_write_len = s->spider_write_off = 0;
    s->spider_write_pending = 0;
#if LC_SPIDER_PROFILE
    if (s->spider_profile_writes == 1u)
        s->spider_profile_opening = spider_profile_now();
    if (s->spider_profile_headers)
        spider_profile_report(s);
#endif
    return lc_spider_fetch_write_complete(s->fetch, 1);
}

static int spider_drain(session *s)
{
    /* handleKeyUpdate holds TLS's write lock until its reply actually reaches the socket. */
    if (s->ku_owed > 0u || s->spider_ku_pending)
        return 0;
    uint8_t *w;
    long           n;
    int terminal_read = 0;
    /* Only while the socket takes what it is given: a Write in the reference returns when the kernel
     * has it, and a writer x/net has stuck writing for good (see reality/fetch.c, spew) writes as
     * fast as that and no faster. The write side drains the rest. */
    for (;;) {
        while (!s->spider_write_pending && q_pending(&s->to_up) == 0) {
            /* Service already queued Writes before continuing buffered input: only
             * this loop can make a producer's TLS Flush complete. This prioritizes
             * runnable I/O, without waiting for that producer's next protocol turn. */
            n = lc_spider_fetch_take(s->fetch, &w);
            if (n < 0)
                return -1;
            if (n == 0)
                break;
#if LC_SPIDER_PROFILE
            s->spider_profile_writes++;
            s->spider_profile_headers = n >= 9 && w[3] == 1u &&
                                       w[5] == 0u && w[6] == 0u && w[7] == 0u && w[8] == 1u;
#endif
            s->spider_write = w;
            s->spider_write_len = (size_t)n;
            s->spider_write_off = 0;
            s->spider_write_pending = 1;
            if (spider_write_complete(s) != 0)
                return -1;
        }
        if (terminal_read)
            return s->spider_write_pending || q_pending(&s->to_up) != 0 ? 0 : -1;
        /* A foreign Write under socket backpressure is not a read barrier. The
         * readLoop still advances until its own Flush or cc.wmu acquisition waits.
         * With no blocked output, drain actual read progress and any new Writes
         * before requesting another record; a zero-progress result ends the turn. */
        int read_rc = lc_spider_fetch_read_step(s->fetch);
        /* A terminal read result cannot discard Writes queued before that
         * result, including plaintext not yet taken by this TLS owner. */
        if (read_rc < 0) {
            terminal_read = 1;
            continue;
        }
        if (s->spider_write_pending || q_pending(&s->to_up) != 0 || read_rc == 0)
            return 0;
    }
}

/* newClientConn Flushes the opening before starting its readLoop and returning
 * to RoundTrip (vendor/x-net/http2/transport.go:543-556). Submit those bytes before
 * pthread creation too, rather than keeping the peer idle through that work.
 * EAGAIN retains the same Write: workers still cannot pass its actual completion,
 * and only the loop touches TLS/socket state. No thread or timed-turn fallback. */
static int spider_start(lc_loop *loop, session *s)
{
    if (spider_tasks_prepare(s) != 0)
        return -1;
    if (spider_drain(s) != 0) {
        note("spider startup fd=%d: initial HTTP/2 Write failed", s->up_fd);
        return -1;
    }
    if (spider_worker_start(loop, s) != 0)
        return -1;
    return spider_drain(s);
}

static int spider_pump(session *s);

static int spider_worker_ready(session *s)
{
#if LC_SPIDER_PROFILE
    if (s->spider_profile_wake == 0u)
        s->spider_profile_wake = spider_profile_now();
#endif
    uint64_t count;
    ssize_t got;
    do {
        got = read(s->spider_wake_fd, &count, sizeof count);
    } while (got < 0 && errno == EINTR);
    if (got < 0 && errno != EAGAIN)
        return -1;
    if (got >= 0 && got != (ssize_t)sizeof count)
        return -1;
    if (spider_workers_reap(s) != 0)
        return -1;
    int rc = atomic_load_explicit(&s->spider_worker_result, memory_order_acquire);
    if (spider_drain(s) != 0)
        return -1;
    s->deadline = lc_spider_fetch_deadline(s->fetch);
    if (rc < 0 || atomic_load_explicit(&s->spider_request_result, memory_order_acquire) < 0) {
        s->spider_end = 1;
        s->deadline = 0;
        return q_pending(&s->to_up) == 0 ? -1 : 0;
    }
    if (!s->spider_peer_lost && s->rx_len > 0u && lc_spider_fetch_read_ready(s->fetch))
        return spider_pump(s);
    return 0;
}

/* What the fetch said after a read or a tick: its writes go out, the backoff it waits on becomes the
 * session's clock, and a connection x/net has closed closes here once they are out — at once when
 * nothing is queued, else from the write side when the queue empties. -1 to close now. */
static int spider_after(session *s, int rc)
{
    if (spider_drain(s) != 0)
        return -1;
    s->deadline = lc_spider_fetch_deadline(s->fetch);
    if (rc != 0) {
        s->spider_end = 1;
        s->deadline = 0;
        if (q_pending(&s->to_up) == 0)
            return -1;
    }
    return 0;
}

/* The VLESS request header, into the request's buffered write. For a datagram session the request is
 * the Mux form xudp rides on; see lc_vless_request_udp. */
static int request_header(session *s, bufw *bw)
{
    uint8_t hdr[UP_REQUEST_HEADER_MAX];
    size_t  hdr_len = 0;
    int     rc = s->plain_udp ? lc_vless_request_udp_plain(s->uuid, s->flow, s->target_host,
                                                       s->target_port, hdr, sizeof hdr, &hdr_len)
                 : s->is_udp  ? lc_vless_request_udp(s->uuid, s->flow, s->target_host, s->target_port,
                                                     hdr, sizeof hdr, &hdr_len)
                           : lc_vless_request(s->uuid, s->flow, s->target_host, s->target_port,
                                              hdr, sizeof hdr, &hdr_len);
    return rc != 0 ? -1 : bufw_write(s, bw, hdr, hdr_len);
}

/* THE REQUEST, WITH THE CLIENT'S FIRST BYTES IN THE SAME WRITE — or alone, once it has waited as long
 * as the reference waits:
 *
 *     multiBuffer, err1 := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
 *     if err1 == nil {
 *         serverWriter.WriteMultiBuffer(multiBuffer)
 *     } else if err1 != buf.ErrReadTimeout { return err1 }
 *     else if requestAddons.Flow == vless.XRV { … an empty padded frame "to camouflage VLESS header" }
 *     bufferWriter.SetBuffered(false)
 *                    (vendor/Xray-core/proxy/vless/outbound/outbound.go:321-344)
 *
 * all of it into the BufferedWriter that already holds the header. `payload == NULL` is the timeout.
 *
 * ⚠️ AND THE TIMEOUT WRITES THE HEADER ALONE, WHICH IS NOT WHAT THOSE LINES SAY. The reader they call is
 * never the pipe itself: the dispatcher wraps every outbound's link in a TimeoutWrapperReader
 * (vendor/Xray-core/app/dispatcher/default.go:197, :341), and that reader's timeout is
 * `case <-timeout: return nil, nil` (vendor/Xray-core/common/buf/io.go:55-77) — no error at all. So the
 * ErrReadTimeout arm with its padding frame is never reached, and the `err1 == nil` arm writes an empty
 * MultiBuffer: VisionWriter frames nothing out of it — `len(mb) == 1 && mb[0] == nil` is false for a
 * nil slice, the loop has no buffers — and BufferedWriter drops the empty result
 * (vendor/Xray-core/common/buf/writer.go:138-141). Written from the outbound's source this first sent
 * the header with a long-padded empty frame, 1293 bytes in two records; the reference client on the
 * local stand, same server, same half second, sent 66 — the header and nothing else — and its debug log
 * never printed "Insert padding with empty content". The client's late bytes still arrive: the
 * wrapper's reading goroutine keeps them for the next ReadMultiBuffer (buf/io.go:39-47), which is the read
 * this client does when the socket becomes readable.
 *
 * ⚠️ THE WAIT ITSELF WAS NOT HERE, and "a single non-blocking read is the 500 ms wait, already served"
 * stood in for it. That is true of a client that speaks first and was already speaking during the
 * handshake. It is not true of a protocol where the server speaks first — SMTP, FTP, POP3, IMAP, MySQL,
 * VNC — or of a request served from the pool, whose client arrived a moment ago: the read found nothing,
 * and this sent the header at once where the reference holds the connection silent for half a second.
 * The first write after a handshake is the most-sampled object on the path, and when it leaves is part
 * of it. */
static int request_write(session *s, const uint8_t *payload, size_t len)
{
    bufw *bw = &request_buf;
    bw->len = 0;
    if (request_header(s, bw) != 0)
        return -1;

    /* A datagram session's first datagram is written by udp_pump, with this header in front of it. */
    if (!s->is_udp && payload != NULL) {
        if (s->use_vision) {
            vision_mb m;
            vision_mb_begin(s, &m);
            vision_mb_scan(s, &m, payload, len);
            vision_mb_ready(s, &m);
            if (vision_mb_write(s, &m, bw, payload, len) != 0)
                return -1;
        } else if (bufw_write(s, bw, payload, len) != 0) {
            return -1;
        }
    }

    if (bufw_flush(s, bw) != 0)
        return -1;
    s->request_due = 0;
    return 0;
}

/* The client's side of the wait: the reader's first read, in its first form — one read of up to
 * buf.Size (see stream_take). End of file before anything comes back from it as io.EOF, which the
 * request returns as an error: the session ends with nothing written. Returns -1 for that, 0
 * otherwise. */
static int request_read(session *s)
{
    uint8_t buf[READ_CHUNK];
    ssize_t got = read(s->lan_fd, buf, sizeof buf);
    if (got == (ssize_t)sizeof buf)
        rv_adjust(s, 1u);
    if (got > 0)
        return request_write(s, buf, (size_t)got);
    if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return 0;
    return -1;
}

/* The tunnel is up: the request waits for the client, for at most REQUEST_WAIT_MS. A datagram session
 * already has what it waits for — the datagram that opened it — so udp_pump writes it now. */
/* XTLS REFUSES UDP/443 UNLESS THE FLOW SAYS OTHERWISE — and it refuses AFTER the dial:
 *
 *     case vless.XRV + "-udp443": allowUDP443 = true; …; fallthrough
 *     case vless.XRV:
 *         switch request.Command {
 *         case protocol.RequestCommandUDP:
 *             if !allowUDP443 && request.Port == 443 {
 *                 return errors.New("XTLS rejected UDP/443 traffic").AtInfo()
 *                    (vendor/Xray-core/proxy/vless/outbound/outbound.go:246-258)
 *
 * sits after `conn` has been dialled and handshaken (:188-200), and the error returns through
 * `defer conn.Close()`. So the node sees a REALITY connection complete and close with close_notify and
 * no request, once for every datagram session the listener would open towards port 443 — which this
 * client refused before dialling, so the node saw nothing.
 *
 * ⚠️ AND ONLY WITH THE VISION FLOW. The check lives inside the XRV case; a request with no flow reaches
 * `default` and carries UDP/443 like anything else. lc_vless_flow_allows_udp443(NULL) is false, and
 * this refused it for a client with no flow too.
 *
 * A refused datagram session is not an error the person sees: the browser is given no UDP path and
 * uses TCP, which is what happens on a network that drops QUIC. */
static int udp443_refused(const session *s)
{
    return s->is_udp && s->target_port == 443u && s->use_vision &&
           !lc_vless_flow_allows_udp443(s->flow);
}

static int request_start(session *s)
{
    if (udp443_refused(s)) {
        stats.udp443_refused++;
        return -1;
    }
    /* `timer := signal.CancelAfterInactivity(ctx, …, ConnectionIdle)`, made before either copy starts. */
    act_set(s, CONNECTION_IDLE_MS);
    s->request_due = 1;
    s->request_by = lc_now_ms() + REQUEST_WAIT_MS;
    if (s->is_udp)
        return udp_pump(s);
    return request_read(s);
}

/* Half a second and nothing: the header goes alone. See request_write. */
static int request_timeout(session *s)
{
    if (request_write(s, NULL, 0) != 0)
        return -1;
    return s->is_udp ? udp_pump(s) : 0;
}


/* WHAT A FAILED REPLY COSTS, which is what the reference's PacketWriter decides by which socket
 * failed (vendor/Xray-core/proxy/dokodemo/dokodemo.go:222-264): a reply to an address of its own goes
 * out of a FakeUDP socket for that address, and a failure closes that socket — `w.conns[*b.UDP] =
 * nil` — to be made again for the next reply; any other reply goes out of the writer's own conn, and
 * a failure there returns the error and ends the downlink, which ends the session. -1 when it ends.
 *
 * EAGAIN and EINTR are not failures and never reach here: Go's WriteTo waits for the socket and goes
 * on, and so does its caller — see reply_wait. ⚠️ UNTIL 2026-09-27 every failure was ignored, and
 * until 2026-09-28 a full socket dropped the datagram. */
static int reply_failed(session *s, int out, const char *from_host)
{
    uint8_t ip[16];
    int     literal = from_host != NULL && from_host[0] != '\0' &&
                  (inet_pton(AF_INET, from_host, ip) == 1 || inet_pton(AF_INET6, from_host, ip) == 1);
    if (!s->udp_unaddressed && literal) {
        for (unsigned i = 0; i < s->dest_count; i++)
            if (s->dests[i].reply_fd == out) {
                close(out);
                s->dests[i].reply_fd = -1;
                break;
            }
        return 0;
    }
    return -1;
}

/* The loop the replies wait on, set once in main: a reply is written from inside the record the node
 * sent, or from inside the Hysteria2 connection, neither of which is handed the loop. */
static lc_loop *reply_loop;

/* THE CLIENT'S SOCKET IS FULL, AND THE REPLY WAITS FOR IT — as the reference's does. Its writer is
 * Go's WriteTo on a descriptor the runtime watches: EAGAIN parks the goroutine until the socket has
 * room and then writes, so the datagram is not lost and nothing after it moves — on the REALITY plane
 * the downlink copy of the whole stream stops there (vendor/Xray-core/proxy/dokodemo/
 * dokodemo.go:222-264), on the Hysteria2 plane that session's writer, with its channel filling
 * behind it (vendor/hysteria/app/internal/tproxy/udp_linux.go:97-110). Until 2026-09-28 this client
 * dropped the datagram and went on.
 *
 * Watched through a duplicate of the socket, because the one that is full can be the listener every
 * other session shares, which is already on the loop for reading and cannot be registered twice; a
 * duplicate is a second descriptor for the same socket, and becomes writable when it does. The
 * session's client-side tag is free for it: a datagram session never registers its client side
 * otherwise. -1 when the wait cannot be set up — no descriptor left, which is the one thing Go's
 * runtime does not run out of here — and the session ends. */
static int reply_wait(session *s, int out)
{
    int fd = fcntl(out, F_DUPFD_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (lc_loop_add(reply_loop, fd, LC_EV_WRITE, &s->lan_tag) != 0) {
        close(fd);
        return -1;
    }
    s->reply_wait_fd = fd;
    return 0;
}

/* A 0x02 stream's datagrams back to the client, as LengthPacketReader reads them: a 16-bit length,
 * then that many bytes in buffers of buf.Size — each of which the transparent inbound's writer sends
 * as a datagram of its own (vendor/Xray-core/proxy/vless/encoding/addons.go:171-191,
 * vendor/Xray-core/proxy/dokodemo/dokodemo.go:222-264) — and a length of
 * zero, an empty MultiBuffer, sends nothing. A packet goes out only once all of it is in, as
 * ReadMultiBuffer returns it; kept aside meanwhile, because it can be 65535 bytes and the queue it
 * arrives through is sized for xudp's. From the one destination the header named, which is the only
 * one this stream has. */
static int plain_datagrams(session *s)
{
    for (;;) {
        size_t         have = q_pending(&s->to_lan);
        const uint8_t *p = s->to_lan.buf + s->to_lan.off;
        if (s->plain_pkt == NULL || (s->plain_got == s->plain_need && s->plain_at >= s->plain_need)) {
            if (have < 2u)
                return 0;
            size_t n = (size_t)p[0] << 8 | p[1];
            s->to_lan.off += 2u;
            have -= 2u;
            p += 2u;
            if (s->plain_pkt == NULL) {
                s->plain_pkt = malloc(65535u);
                if (s->plain_pkt == NULL)
                    return own_failure(s);
            }
            s->plain_need = n;
            s->plain_got = 0;
            s->plain_at = 0;
            s->reply_counted = 0;
        }
        size_t take = s->plain_need - s->plain_got;
        if (take > have)
            take = have;
        memcpy(s->plain_pkt + s->plain_got, p, take);
        s->plain_got += take;
        s->to_lan.off += take;
        if (s->to_lan.off >= s->to_lan.len)
            s->to_lan.len = s->to_lan.off = 0;
        if (s->plain_got < s->plain_need)
            return 0;

        /* One packet, one MultiBuffer, one Update — a zero-length one is empty and moves nothing
         * (vendor/Xray-core/common/buf/copy.go:27-31). Once, however many attempts the writing
         * takes: the timer moves when the reader hands the packet over, not when it goes. */
        if (!s->reply_counted) {
            if (s->plain_need > 0u)
                act_update(s);
            s->reply_counted = 1;
        }
        int out = reply_socket_for(s, s->target_host, s->target_port);
        if (out < 0)
            s->plain_at = s->plain_need;
        while (s->plain_at < s->plain_need) {
            size_t at = s->plain_at;
            size_t n = s->plain_need - at < XUDP_READ_SIZE ? s->plain_need - at : XUDP_READ_SIZE;
            if (sendto(out, s->plain_pkt + at, n, MSG_NOSIGNAL, (struct sockaddr *)&s->peer,
                       s->peer_len) < 0) {
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return reply_wait(s, out);
                if (reply_failed(s, out, NULL) != 0)
                    return -1;
            }
            stats.udp_bytes_down += n;
            s->plain_at += n;
        }
        if (out == s->lan_fd && s->plain_need > 0u)
            udp_seen(s);
    }
}

/* Sends every whole datagram the queue now holds back to the client it came from, and leaves what
 * is not yet whole for the next record. */
static int flush_datagrams(session *s)
{
    /* The writer is waiting for the client's socket; what arrives meanwhile stays in the queue, and
     * the node is not read once that is full — see reply_wait and udp_reply_ready. */
    if (s->reply_wait_fd >= 0)
        return 0;
    if (s->plain_udp)
        return plain_datagrams(s);
    for (;;) {
        const uint8_t *payload = NULL;
        size_t         payload_len = 0, used = 0;
        /* The address the frame states is read and NOT enforced, deliberately.
         *
         * Every xudp frame says where its datagram belongs, which is what lets one session serve
         * many destinations — see vless/xudp.h.
         *
         * ⚠️ AND THE FIELD IS NOT REDUNDANT, WHICH IS WHAT THIS SAID UNTIL THE MODEL CHANGED UNDER
         * IT. The sentence here was "this client still opens a stream per destination, so today the
         * answer is known before the frame is read" — true while a datagram session belonged to a
         * client AND one address, and false since it began belonging to the client alone
         * (udp_session_for). The address is now the only thing that says which of this client's
         * destinations a reply came from, and the code twenty lines down picks the reply socket
         * with it. A comment calling a load-bearing field redundant is how the load-bearing part
         * gets deleted by somebody tidying.
         *
         * ⚠️ AND COMPARING IT TO THE DESTINATION WOULD BE WRONG, not merely useless. A request goes
         * out as a NAME when the client asked for a name; the node resolves it and answers from the
         * ADDRESS it reached. Requiring the two to match would drop every reply to a name — the
         * ordinary case for a resolver — while looking like a strictness improvement. */
        /* 256, not LC_HY_ADDR_MAX: that name lives in the Hysteria plane's header, and this
         * function is compiled into the build WITHOUT it too — `make check` builds both and caught
         * exactly that. A domain is at most 255 bytes plus the terminator, which is the bound the
         * frame's own length byte enforces. */
        char           from_host[256];
        uint16_t       from_port = 0;
        int            r = lc_xudp_next(s->to_lan.buf + s->to_lan.off, q_pending(&s->to_lan),
                                        from_host, sizeof from_host, &from_port, &payload,
                                        &payload_len, &used);
        if (r < 0)
            return -1;
        if (r == 0)
            return 0;
        /* The node ended the stream. Handed up rather than turned into a failure here, so that it
         * reaches the same place a peer's end-of-stream already reaches — see LC_XUDP_ENDED.
         *
         * ⚠️ AND WHAT IS LEFT IN THE BUFFER IS DROPPED, which is not tidying. session_done calls a
         * datagram session finished on `up_eof && q_pending(&s->to_lan) == 0`, and the frame that
         * said "ended" is still sitting there unconsumed — so leaving it would hold the predicate
         * false for ever and the session would be collected by the idle sweep a minute later, which
         * is the exact lateness that predicate exists to avoid. Every frame BEFORE this one was
         * already parsed and sent by the loop above; nothing after it is deliverable, because the
         * stream it belonged to is over. The reference does the same thing by releasing its buffer
         * and returning io.EOF (vendor/Xray-core/common/xudp/xudp.go:164-181). */
        if (r == LC_XUDP_ENDED) {
            s->to_lan.len = s->to_lan.off = 0;
            return LC_XUDP_ENDED;
        }

        /* WHICH OF THIS CLIENT'S ADDRESSES ANSWERED, and therefore which socket may answer as it.
         *
         * This is what the address in the frame is for. One stream carries every destination the
         * client is talking to, so a reply is only attributable by what it says about itself — and
         * the socket it goes out of has to be the one bound to that address, or the client sees an
         * answer from a host that is not the one answering. One the client never sent to gets a
         * socket of its own, as the reference's writer makes one — see reply_socket_for.
         *
         * A frame with no address lands here with an empty host and no bytes, and goes to the first
         * destination's socket with nothing to send. That is a Keep whose option bit says no
         * payload follows — NOT the End frame, which this sentence used to name. End never reached
         * this line: the parser refused status 0x03 as impossible framing, so the case described
         * here could not execute. It now returns LC_XUDP_ENDED and never arrives as a frame at all. */
        /* `timer.Update()` for every MultiBuffer the reader hands the copy, and xudp's reader hands one
         * per datagram with a payload — a KeepAlive, a Keep with no payload and a discarded frame hand
         * nothing (vendor/Xray-core/common/xudp/xudp.go:150-202, vendor/Xray-core/proxy/vless/
         * encoding/encoding.go:188-191). ⚠️ UNTIL 2026-09-27 once per record, whatever it held. */
        /* Once per frame, however many attempts the writing takes — see reply_wait. */
        int counted = s->reply_counted;
        if (payload_len > 0 && !counted)
            act_update(s);
        s->reply_counted = 1;
        int out = reply_socket_for(s, from_host, from_port);

        /* A short send on a datagram socket does not happen: either the whole thing goes or nothing
         * does. A refusal is dropped, as the reference's writer drops it — and a socket with no room
         * is waited for, as it waits: the frame stays at the front of the queue until it has gone. */
        if (out >= 0 && payload_len > 0) {
            /* udpConn.Write — which only the configured-destination form goes through: dokodemo
             * writes to the conn itself when the destination was not overridden, and in TPROXY mode
             * through a FakeUDP socket of the destination's own that never touches the conn
             * (vendor/Xray-core/proxy/dokodemo/dokodemo.go:163-187), so no activity is recorded
             * (Write is the only updateActivity on that side, vendor/Xray-core/app/proxyman/inbound/
             * worker.go:214-224). ⚠️ EVERY REPLY REFRESHED THE SESSION HERE UNTIL 2026-09-27: a
             * transparent session where only the far side talked lived on past the idle check that
             * closes Xray's two to three minutes after the client's last datagram. */
            if (out == s->lan_fd && !counted)
                udp_seen(s);
            for (;;) {
                if (sendto(out, payload, payload_len, MSG_NOSIGNAL, (struct sockaddr *)&s->peer,
                           s->peer_len) >= 0) {
                    stats.udp_bytes_down += payload_len;
                    break;
                }
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return reply_wait(s, out);
                if (reply_failed(s, out, from_host) != 0) {
                    s->to_lan.off += used;
                    return -1;
                }
                break;
            }
        }
        s->reply_counted = 0;
        s->to_lan.off += used;
        if (s->to_lan.off >= s->to_lan.len)
            s->to_lan.len = s->to_lan.off = 0;
    }
}

/* ---- the node's records once the handshake is over ------------------------------ */

/* ⚠️ THE NODE'S RECORDS ARE READ AS uTLS READS THEM ONCE THE HANDSHAKE IS OVER — decided in
 * tls/post.c, and done here, wherever this client reads them: the stream (deliver_record), a tunnel
 * dialled ahead of need (spare_read) and the spider's page (spider_read), three readers of the one
 * tls.Conn the reference has for all of it.
 *
 * Before this a record that did not open ended the connection with close_notify alone, and
 * everything that opened but was not application data was dropped. Several of the reference's
 * refusals answer bytes anybody on the path can write — a record header, a record that does not
 * open, a ChangeCipherSpec, which is never encrypted — so the difference needed no key to be seen.
 * tools/vendorcap/nodealert runs both clients against a node that misbehaves on purpose. */

/* What node_record makes of a record besides 0 (taken, nothing for the caller) and -1 (the
 * connection is over): application data with bytes in it, for the caller; and close_notify, the
 * end of the node's stream — io.EOF to the reference, and the same up_eof a closed socket gives
 * here. Not 2, which deliver_record returns for LC_XUDP_ENDED. */
#define NODE_DATA   1
#define NODE_CLOSED 3

/* The alert the reference sends — once, or twice for a type uTLS does not know — and then the end
 * of the connection.
 *
 * `c.in.setErrorLocked(c.sendAlert(...))`: an alert record sealed with the current write key. Queued
 * behind whatever is still going to the node, as the reference's sendAlert waits on the write lock
 * for a Write in progress; flushed now, and what cannot leave before the close is lost — the
 * reference would block for it, and a connection being torn down here does not. The close that
 * follows adds close_notify only when the queue has drained, which is tls.Conn.Close's rule for a
 * Write still under way (see where session_close seals it). */
static int node_refuse(session *s, uint8_t alert, unsigned times, const char *why)
{
    uint8_t rec[LC_CLIENT_ALERT_MAX];
    for (unsigned i = 0; i < times; i++) {
        size_t n = lc_client_alert_record(&s->cl, alert, rec, sizeof rec);
        if (n == 0 || q_push(&s->to_up, rec, n) != 0)
            break;
    }
    (void)q_flush(&s->to_up, s->up_fd);
    note("the node sent %s: alert %u back, and the connection ends", why, (unsigned)alert);
    return -1;
}

/* What tls/post.c decided, done.
 *
 * ⚠️ ITS CALLERS TAKE THE VERDICT INTO A VARIABLE FIRST. `node_verdict(s, lc_post_header(hdr,
 * &alert, &why), alert, why)` reads `alert` in whatever order the compiler picks relative to the
 * call that sets it, and gcc picked "before": every refusal on the nodealert stand went out as
 * alert 0 — close_notify, the right length on the wire and the wrong byte inside. */
static int node_verdict(session *s, int v, uint8_t alert, const char *why)
{
    switch (v) {
    case LC_POST_TAKEN:
        return 0;
    case LC_POST_DATA:
        return NODE_DATA;
    case LC_POST_CLOSED:
        return NODE_CLOSED;
    case LC_POST_REFUSED:
        return node_refuse(s, alert, 1u, why);
    case LC_POST_TWICE:
        return node_refuse(s, alert, 2u, why);
    case LC_POST_ENDED:
        /* The node's own alert — its number is worth the log line; a KeyUpdate has none. */
        if (alert != 0u)
            note("the node sent %s, %u; the connection ends", why, (unsigned)alert);
        else
            note("the node sent %s; the connection ends", why);
        return -1;
    default:
        return own_failure(s); /* no memory for a message arriving in pieces */
    }
}

/* The five bytes in front of a record, checked before its body is waited for. Their ceiling is
 * what `rx` holds, so the check that used to end the connection here in silence is the same
 * comparison, with the reference's alert. */
static int node_header(session *s, const uint8_t *hdr)
{
    uint8_t     alert = 0;
    const char *why = "";
    int         v = lc_post_header(&s->post, hdr, &alert, &why);
    return node_verdict(s, v, alert, why);
}
_Static_assert(MAX_REC == LC_REC_HEADER + LC_REC_MAX_PLAINTEXT + 2048u,
               "lc_post_header's ceiling, TLS 1.2's the larger, is what a session's rx holds");

/* Opens one whole record, `rec`. A ChangeCipherSpec is never opened and always refused; a record
 * that does not open draws the number the record layer names — see lc_record_unprotect. */
static int node_open(session *s, const uint8_t *rec, size_t rec_len, uint8_t *plain, size_t cap,
                     size_t *plain_len, uint8_t *inner)
{
    uint8_t     alert = 0;
    const char *why = "";
    if (rec[0] == LC_REC_CHANGE_CIPHER_SPEC) {
        int v = lc_post_ccs(&s->post, rec + LC_REC_HEADER, rec_len - LC_REC_HEADER, &alert, &why);
        (void)node_verdict(s, v, alert, why);
        return -1;
    }
    /* Opened already on another core, when that was done from these very inputs and it opened —
     * otherwise opened here, as always. See tls/recopen.h. DIVERGES: O3. */
    if (lc_recopen_take(recopen, &s->cl.rd, rec, rec_len, plain, cap, plain_len, inner)) {
        stats.rec_ahead++;
        return 0;
    }
    int rc = lc_record_unprotect(&s->cl.rd, rec, rec_len, plain, cap, plain_len, inner);
    if (rc != 0)
        return node_refuse(s, (uint8_t)-rc, 1u, "a record that does not open");
    return 0;
}

/* The answers owed, each as it finds room: sealed with the write key in force, written as every
 * record is — straight to the socket when nothing waits ahead of it, else behind what does, see
 * conn_write — counted in the bytes sent (see tls_write), and only then the write key one generation
 * on, so the next answer and every record after it are sealed with the new one. -1 when a key cannot
 * be built or the socket failed.
 *
 * ⚠️ NOT PUSHED AND THEN FLUSHED, which is what this did, and it froze uploads. The flush drained
 * the queue towards the node from the READ side; with a multi-buffer write half done (up_n), that
 * write goes on only from the write side's event, which an empty queue no longer arms, while the
 * client's reads stay shut until it is finished — so nothing ever came back to it. The nodealert
 * stand's kufull: a KeyUpdate in the middle of a 48 MB upload, the reference carried all of it and
 * this stopped at 3 MB and sat there. conn_write never drains what is already queued. */
static int ku_settle(session *s)
{
    if (s->st == ST_SPIDER) {
        if (s->spider_write_pending)
            return 0; /* The application Write still owns TLS's write lock. */
        if (s->spider_ku_pending) {
            if (q_pending(&s->to_up) > 0u)
                return 0;
            s->spider_ku_pending = 0;
        }
    }
    while (s->ku_owed > 0u) {
        uint8_t rec[LC_CLIENT_KEY_UPDATE_MAX];
        if (s->to_up.cap - q_pending(&s->to_up) < sizeof rec)
            return 0;
        size_t n = lc_client_key_update_record(&s->cl, rec, sizeof rec);
        if (n == 0 || conn_write(s, rec, n) != 0)
            return -1;
        s->tls_bytes_sent += n;
        s->ku_owed--;
        if (lc_client_update_write(&s->cl) != 0)
            return -1;
        if (s->st == ST_SPIDER && q_pending(&s->to_up) > 0u) {
            s->spider_ku_pending = 1;
            return 0;
        }
    }
    return 0;
}

/* handleKeyUpdate on this side (vendor/utls/conn.go:1345-1382): the read key one generation on, and
 * when the node asked, the answer and then the write key.
 *
 * ⚠️ A QUEUE WITH NO ROOM FOR THE ANSWER ENDED THE CONNECTION, where the reference waits: the answer
 * is written under `c.out.Lock()` from inside Read, so the reader stays in handleKeyUpdate until a
 * Write in progress has let go of the lock and the socket has taken the 27 bytes — and reads nothing
 * from the node meanwhile. So an answer that does not fit is owed rather than refused: ku_settle
 * writes it from the write side as soon as the queue has drained enough (see where to_up is flushed),
 * and session_rearm does not read the node until it has. Nothing sealed later can overtake it — the
 * write key moves only when the answer is sealed, and the uplink's reads, which arm on a room far
 * larger than 27 bytes, are shut while less than that is free.
 *
 * What the reader had already taken is still read. The reference reads nothing past the KeyUpdate
 * until its answer is written; here the records already in hand are opened and handed on — which
 * reaches only the client on the LAN, and only sooner. A second KeyUpdate among them is owed behind
 * the first, and answered with the key the first moved to, as the reference answers it. */
static int node_key_update(void *ctx, int requested)
{
    session *s = ctx;
    if (lc_client_update_read(&s->cl) != 0)
        return -1;
    if (!requested)
        return 0;
    s->ku_owed++;
    return ku_settle(s);
}

/* What an opened record is. */
static int node_record(session *s, const uint8_t *plain, size_t plain_len, uint8_t inner)
{
    uint8_t     alert = 0;
    const char *why = "";
    s->post.key_update = node_key_update;
    s->post.ctx = s;
    int         v = lc_post_record(&s->post, plain, plain_len, inner, &alert, &why);
    return node_verdict(s, v, alert, why);
}

/* Declared here because the raw path is set up from inside record delivery — the announcement that
 * ends the framed stream is itself the last thing to arrive framed. */
static int splice_arm(session *s);

/* Opens the record `rec`, whole in s->rx, and queues its contents for the client.
 *
 * A record that does not authenticate ends the connection rather than being skipped: on this path a
 * failed tag means either the node is not who we think, or our own key schedule has drifted, and
 * carrying on past either is worse than stopping. What is not application data with bytes in it is
 * node_record's, and never reaches the client. */
static int deliver_record(session *s, const uint8_t *rec, size_t rec_len)
{
    uint8_t *plain = scratch.plain;
    size_t   plain_len = 0;
    uint8_t  inner = 0;
    int      rc = 0;
    /* How far the unpadded buffer was written, so the wipe at the end covers exactly that. */
    size_t   unpadded_len = 0;

    int opened = node_open(s, rec, rec_len, plain, sizeof scratch.plain, &plain_len, &inner);
    if (opened != 0)
        return opened;

    stats.rec_in++;
    stats.bytes_in += plain_len;

    rc = node_record(s, plain, plain_len, inner);
    if (rc != NODE_DATA)
        goto out;
    rc = 0;

    if (inner == LC_REC_APPLICATION_DATA && plain_len > 0) {
        const uint8_t *body_p = plain;
        size_t         body_n = plain_len;

        if (!s->vless_header_seen) {
            /* From the stream, as DecodeResponseHeader reads it: across records, and with the
             * addons unmarshalled — a refusal there ends the session as the reference's error ends
             * its Process. ⚠️ UNTIL 2026-09-27 the whole header had to be in the first record and
             * the addons were stepped over unread. */
            size_t vh = 0;
            int    hr = lc_vless_response_feed(&s->vresp, plain, plain_len, &vh);
            if (hr < 0) {
                rc = -1;
                goto out;
            }
            body_p += vh;
            body_n -= vh;
            if (hr == 1)
                s->vless_header_seen = 1;
        }

        uint8_t *un = scratch.unpadded;
        if (s->use_vision && body_n > 0) {
            size_t got_un = 0;
            int    direct = 0;
            if (lc_vision_read(&s->vision, body_p, body_n, un, sizeof scratch.unpadded, &got_un,
                               &direct) != 0) {
                rc = -1;
                goto out;
            }
            body_p = un;
            body_n = got_un;
            unpadded_len = got_un;

            /* The filter saw this direction inside lc_vision_read, read by read, and that is not
             * symmetry for its own sake: what it is looking for is a ServerHello, and a ServerHello
             * only ever arrives here. Feeding it only the outbound stream — which is what this did
             * at first — leaves it unable to conclude anything, and the upstream direction then
             * stays padded and doubly encrypted for the life of the connection. */
            /* Set after unpadding, not before: the frame carrying the announcement still ends with
             * real data, and that data is still inside this record. Only what comes after it on the
             * socket is raw. */
            if (direct && !s->direct_in) {
                /* The copier goes to splice, and the timer with it: `timer.SetTimeout(24 * time.Hour)`
                 * (vendor/Xray-core/proxy/proxy.go:774) — after the Update this record's bytes make
                 * below, as the reference makes it on the read that carried the command. */
                act_set(s, SPLICE_IDLE_MS);
                /* A pipe that cannot be had is a slower connection, not a dead one — the framing and
                 * the second decryption are gone either way, and those were the expensive part. */
                int spliced = splice_arm(s) == 0;
                if (spliced) stats.pipes_armed++; else stats.pipes_failed++;
                if (log_per_connection())
                    note("direct copy engaged for %s:%u%s", s->target_host, s->target_port,
                           spliced ? "" : " (copied, no pipe available)");
                /* ⚠️ BUT A FAILURE IS ALWAYS SAID, and that is not the same as the line above.
                 * Success is routine: 92 % of arriving bytes get the hand-off to the kernel, and
                 * logging every one of them means erasing the log. A failure means pipe2 gave no
                 * pipe — on a router that is the descriptor limit reached, which is the warning
                 * that connections are about to be refused too. That must not wait until somebody
                 * asks for a summary.
                 *
                 * Without the address and rate-limited: the address diagnoses nothing here — a pipe
                 * is not about where the connection is going — and the reason failures arrive in a
                 * burst is exactly one per box. One line, then a counter, then silence: the same
                 * shape as the datagram-session refusal a floor below. */
                if (!spliced) {
                    static uint64_t said_at;
                    uint64_t        now = lc_now_ms();
                    if (said_at == 0u || now - said_at >= 60000u) {
                        note("no pipe for a direct copy: the kernel would not give one — a local "
                             "limit, and the summary carries how often");
                        said_at = now;
                    }
                }
            }
            s->direct_in = direct;
        }

        if (s->is_udp) {
            /* Datagrams are reassembled in the queue and sent whole, never partially: a UDP client
             * that receives half a reply has received a wrong answer, not a slow one. Whatever does
             * not yet make a complete one stays for the next record. The timer moves per datagram
             * delivered, not per record: see flush_datagrams. */
            if (body_n > 0 && q_push(&s->to_lan, body_p, body_n) != 0)
                rc = -1;
            else
                rc = flush_datagrams(s);
        } else {
            /* XtlsRead's `timer.Update()` on every non-empty read (vendor/Xray-core/proxy/vless/
             * vless/encoding/encoding.go:188-191). */
            if (body_n > 0 && !s->direct_in)
                act_update(s);
            if (body_n > 0 && q_push(&s->to_lan, body_p, body_n) != 0)
                rc = -1;
            else if (q_flush(&s->to_lan, s->lan_fd) != 0)
                rc = -1;
        }
    }

out:
    /* Wiped before the next record reuses them: both of these held the plaintext of whatever the
     * user is doing, and the scratch is shared by every connection at once.
     *
     * As far as each was written, not to the end of the buffer. Beyond that lies the previous
     * record's plaintext, which was wiped when IT was the current one — so clearing the whole
     * sixteen kilobytes clears the same bytes a second time. At an average record of just under
     * four kilobytes that is four times the wiping, and on a twenty-megabyte download it came to
     * ninety-seven megabytes of memset for twenty megabytes of traffic.
     *
     * The unpadded buffer was not being wiped at all, which was the more serious half: it holds
     * the same plaintext with Vision's framing removed, and it outlived every record. */
    lc_wipe(scratch.plain, plain_len);
    lc_wipe(scratch.unpadded, unpadded_len);
    return rc;
}

/* THE RAW BYTES A READ TOOK PAST THE ANNOUNCEMENT, handed to the client ahead of everything the raw
 * connection gives after them — see the end of records_ready for how they got here and what the
 * reference does with them.
 *
 * Resume after Flush drains the queue and creates room. Returning with
 * an unqueued tail is safe only behind a full pending writer; otherwise no new
 * event need arrive to deliver it. VisionReader.ReadMultiBuffer merges input and
 * rawInput before its caller writes that MultiBuffer (vendor/Xray-core/proxy/proxy.go:259-288). */
static int raw_carry(session *s)
{
    for (;;) {
        size_t room = q_room(&s->to_lan);
        size_t n = s->rx_len < room ? s->rx_len : room;
        if (n > 0u) {
            if (q_push(&s->to_lan, s->rx, n) != 0)
                return -1;
            s->rx_len -= n;
            memmove(s->rx, s->rx + n, s->rx_len);
        }
        if (q_flush(&s->to_lan, s->lan_fd) != 0)
            return -1;
        if (s->rx_len == 0u || q_room(&s->to_lan) == 0u)
            return 0;
    }
}

/* ---- reading the node's side, as the reference reads it ----------------------------------------
 *
 * Every read of the node's socket — in the handshake, while a spare waits, in the spider and on an
 * open tunnel without threads to open records ahead (O3's reads are node_read_ahead's) — asks for
 * what uTLS would ask for at the same point: readFromUntil on its rawInput, whose shape `rin` keeps
 * (tls/rawin.h). This used to ask for a record's missing bytes exactly, and later for as much as the
 * session's buffer held; both left a different amount in the socket than the reference leaves, and
 * that is on the wire the moment the connection is closed with bytes unread — a reset where the
 * reference sends a FIN, or the other way round. The nodealert stand's `huge` is the one that
 * showed it. */

/* The session's storage, as large as the reference's buffer has grown: what it holds at the front,
 * and room behind it for the read lc_rawin_ask has just sized. -1 when the memory cannot be had,
 * which ends the session as the reference's allocation failing ends its process. */
static int rx_fit(session *s)
{
    size_t cap = lc_rawin_cap(&s->rin);
    if (cap <= s->rx_cap)
        return 0;
    uint8_t *big = malloc(cap);
    if (big == NULL)
        return own_failure(s);
    memcpy(big, s->rx, s->rx_len);
    if (s->rx != s->rx_small) {
        lc_wipe(s->rx, s->rx_cap);
        free(s->rx);
    } else {
        lc_wipe(s->rx_small, s->rx_len);
    }
    s->rx = big;
    s->rx_cap = cap;
    return 0;
}

/* What readRecordOrCCS waits for at the front of the buffer (vendor/utls/conn.go:630-688): the
 * header, and once it has been judged — every caller judges it before it asks again — the whole
 * record. */
static size_t node_want(const session *s)
{
    if (s->rx_len < LC_REC_HEADER)
        return LC_REC_HEADER;
    return LC_REC_HEADER + ((size_t)s->rx[3] << 8 | s->rx[4]);
}

/* One read towards `n` bytes at the front, of the size uTLS's would be. 1 when bytes came; 0 when
 * the buffer holds n already or the socket had nothing yet; -2 at the node's end of stream; -1 on a
 * socket error or no memory. */
static int node_fill(session *s, size_t n)
{
    size_t ask = lc_rawin_ask(&s->rin, n);
    if (ask == 0u)
        return 0;
    if (rx_fit(s) != 0)
        return -1;
    ssize_t got = read(s->up_fd, s->rx + s->rx_len, ask);
    if (got > 0) {
        s->rx_len += (size_t)got;
        lc_rawin_got(&s->rin, (size_t)got);
        return 1;
    }
    if (got == 0)
        return -2;
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
}

/* A record taken from the front — rawInput's Next — and the rest moved up. */
static void rx_take(session *s, size_t n)
{
    lc_rawin_next(&s->rin, n);
    s->rx_len -= n;
    memmove(s->rx, s->rx + n, s->rx_len);
}

/* ---- an open tunnel reads ahead of the reference, and the reference follows in the shadow --------
 *
 * The threads that open records ahead (O3) need several records in hand at once, and a read of the
 * reference's size brings two. So on an open tunnel the socket is read a bufferful at a time — up to
 * RX_BIG — and `rin` is not what sizes the reads any more but what the reference WOULD have read by
 * now: readFromUntil runs against the bytes already in hand, each of its reads getting what it asks
 * for or what is there, and what has been read past it is `rin_ahead`.
 *
 * Nothing of this reaches the wire but one thing, and that one thing is kept: a connection closed
 * with bytes unread goes out as a reset, and the reference closes with a reset exactly when it has
 * left bytes in the socket. Those bytes are `rin_ahead` plus whatever neither of us has read; so a
 * close with `rin_ahead` above zero is made a reset here (session_close), and the rest the kernel
 * decides for both. The nodealert stand's `huge` — a header refused on a fresh connection after the
 * reference had read 576 bytes of 16 646 — is the case it was measured on. DIVERGES: O3. */

/* A session's buffer grows to this while it carries a stream: four records of the largest size, one
 * for the loop and one for each thread on the MT7621's four. See rx_resize. */
#define RX_BIG (4u * MAX_REC)

/* readFromUntil(n) as the reference would have made it, served from the bytes already read: 1 when
 * the reference's buffer holds n, 0 when it would still be waiting for bytes not read yet. */
static int rin_until(session *s, size_t n)
{
    for (;;) {
        size_t ask = lc_rawin_ask(&s->rin, n);
        if (ask == 0u)
            return 1;
        if (s->rin_ahead == 0u)
            return 0;
        size_t got = ask < s->rin_ahead ? ask : s->rin_ahead;
        lc_rawin_got(&s->rin, got);
        s->rin_ahead -= got;
    }
}

/* The session's buffer on an open tunnel: RX_BIG from the heap once a read has filled a smaller one
 * — the node had more waiting than was asked for — and the small one again once a read comes in
 * under a record and what is left fits in it. The smaller one may be rx_fit's, as large as the
 * reference's buffer grew in the handshake. A buffer that cannot be had leaves the session as it
 * was. */
static void rx_resize(session *s, size_t got, size_t asked)
{
    if (s->rx_cap < RX_BIG) {
        if (got < asked)
            return;
        uint8_t *big = malloc(RX_BIG);
        if (big == NULL)
            return;
        memcpy(big, s->rx, s->rx_len);
        if (s->rx != s->rx_small) {
            lc_wipe(s->rx, s->rx_cap);
            free(s->rx);
        } else {
            lc_wipe(s->rx_small, s->rx_len);
        }
        s->rx = big;
        s->rx_cap = RX_BIG;
        return;
    }
    if (got >= MAX_REC || s->rx_len > sizeof s->rx_small)
        return;
    memcpy(s->rx_small, s->rx, s->rx_len);
    lc_wipe(s->rx, s->rx_cap);
    free(s->rx);
    s->rx = s->rx_small;
    s->rx_cap = sizeof s->rx_small;
}

/* One read on an open tunnel, as much as the buffer holds. 1 when bytes came; 0 when the socket had
 * nothing; -2 at the node's end of stream; -1 on a socket error. */
static int node_read_ahead(session *s)
{
    size_t room = s->rx_cap - s->rx_len;
    /* Full of whole records the client has no room for yet: a read of nothing would be taken for
     * the node's end. */
    if (room == 0u)
        return 0;
    ssize_t got = read(s->up_fd, s->rx + s->rx_len, room);
    if (got > 0) {
        s->rx_len += (size_t)got;
        s->rin_ahead += (size_t)got;
        rx_resize(s, (size_t)got, room);
        return 1;
    }
    if (got == 0)
        return -2;
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
}

/* EVERY WHOLE RECORD THE BUFFER ALREADY HOLDS, as far as there is room to put what comes out.
 *
 * ⚠️ AND IT IS CALLED FROM TWO PLACES, which is the whole reason it is a function. Delivering a
 * record pushes plaintext into the queue towards the client and flushes it; if that client is slow
 * the queue stays full, and this stops with a whole record still in hand. Nothing would then read
 * it: the node may have nothing more to send, so no read event is coming, and the write event that
 * eventually drains the client used to lead nowhere near here. So the write side calls it too.
 *
 * Returns -1 when the session is over. `up_eof` is set rather than returned, as its caller had it. */
static int records_ready(session *s)
{
    /* Nothing past the node's end is read. After its close_notify the reference's every read
     * answers io.EOF — setErrorLocked keeps the first error (vendor/utls/conn.go:723-725) — and after
     * an xudp End the reader has returned; records that came in the same read as either stay where
     * they are. The read side stops being armed at up_eof (session_rearm), but the write side calls
     * this too, and it used to carry on through them.
     *
     * ⚠️ NO STAND HAS REACHED THIS YET. It matters only when the close_notify is taken while the queue
     * to the client still holds bytes, so that a write event comes back afterwards; on loopback the
     * flush just before it empties the queue every time — nodealert's closeslow, 8 MB to a reader
     * with a 4 KB window reading a millisecond at a time, let a build without these two lines pass
     * three times. It is the reference's rule all the same, and the state is socket timing. */
    if (s->up_eof)
        return 0;

    /* The records are taken from `at` onwards and the buffer is moved once, at the end, rather than
     * after every record as it was: the threads that open records ahead read them where they lie,
     * and nothing may move under them until lc_recopen_finish — see tls/recopen.h. */
    size_t at = 0;
    int    rc = 0, handed = 0, direct = 0;
    for (;;) {
        const uint8_t *rec = s->rx + at;
        size_t         have = s->rx_len - at;
        /* readFromUntil for the header, then — once it has been judged — for the whole record, as
         * readRecordOrCCS makes them (vendor/utls/conn.go:630-688); rin_until is 0 exactly when
         * the bytes are not in hand yet. */
        if (have < LC_REC_HEADER || !rin_until(s, LC_REC_HEADER))
            break;

        size_t body = (size_t)rec[3] << 8 | rec[4];
        if (node_header(s, rec) != 0) {
            rc = -1;
            break;
        }

        size_t whole = LC_REC_HEADER + body;
        if (have < whole || !rin_until(s, whole))
            break;

        /* The room one record's plaintext needs, asked before the record is opened rather than
         * after: this is the same guarantee session_rearm makes before arming the node's side, and
         * it has to hold for the second record of a read as much as for the first. */
        if (q_room(&s->to_lan) < LC_REC_MAX_PLAINTEXT)
            break;

        /* The whole records this read holds, handed to the other cores once, before the first of
         * them is opened here. DIVERGES: O3. */
        if (!handed) {
            handed = 1;
            if (!recopen_tried && have > whole) {
                recopen_tried = 1;
                if (lc_recopen_new(&recopen) != 0)
                    recopen = NULL;
            }
            stats.rec_handed += lc_recopen_start(recopen, &s->cl.rd, rec, have);
        }

        int dr = deliver_record(s, rec, whole);
        at += whole;
        lc_rawin_next(&s->rin, whole);
        /* The node's close_notify is its end of stream, io.EOF to the reference, and goes the way a
         * closed socket goes — including the way it goes before the VLESS response has arrived,
         * which is the end of the session: DecodeResponseHeader fails on it and the whole Process
         * ends (see the read of the node's side in the loop). Answered with up_eof alone, a node
         * that said close_notify first was left with a connection held open that the reference
         * closes at once — the nodealert stand's `close`. */
        if (dr == NODE_CLOSED && !s->vless_header_seen) {
            rc = -1;
            break;
        }
        if (dr == LC_XUDP_ENDED || dr == NODE_CLOSED) {
            s->up_eof = 1;
        } else if (dr != 0) {
            rc = -1;
            break;
        }

        /* ⚠️ AFTER THE RECORD THAT ANNOUNCED DIRECT COPY, WHAT IS LEFT IN THE BUFFER IS NOT RECORDS.
         * The node stops framing right after it, so the rest of this read is the target's own bytes,
         * raw — and this loop went on parsing them as records. Whatever that made of them, the
         * download was cut: on the stand's tlsdown the client got 95 306, 1 186, 4 096 and 3 558 of
         * 300 120 bytes in four runs out of six, from the day this side began reading a bufferful
         * at a time. Before that a read never went past the record it was finishing, so
         * the raw bytes were still in the socket for splice to take.
         *
         * The reference hands them on with the read that carried the command, ahead of anything the
         * raw connection gives next: `input` and `rawInput`, what its tls.Conn had read but not
         * returned, are merged into that same buffer before the reader is swapped for the raw one
         * (vendor/Xray-core/proxy/proxy.go:259-273). Here they go into the queue towards the client,
         * which direct_pump drains before anything else moves — see raw_carry. */
        if (s->direct_in) {
            direct = 1;
            break;
        }
        if (s->up_eof)
            break;
    }

    /* The threads let go of the buffer first — what they opened and nobody took is wiped — and only
     * then is what is left moved to the front: a partial record, records there was no room for, or
     * the raw bytes behind the announcement. */
    lc_recopen_finish(recopen);
    if (at > 0u) {
        memmove(s->rx, s->rx + at, s->rx_len - at);
        s->rx_len -= at;
    }
    /* After the announcement of direct copy the reference reads the socket raw, and what was read
     * here ahead of it is what it reads next: nothing of it is left behind any more. */
    if (direct)
        s->rin_ahead = 0;
    if (rc == 0 && direct)
        return raw_carry(s);
    return rc;
}

/* What each descriptor should be watched for right now.
 *
 * This is where backpressure lives, and it is one rule: a side is read from only while there is
 * somewhere to put what it says. Without it a fast node and a slow client meet in an unbounded
 * buffer, and the device runs out of memory rather than slowing down. */
static int session_rearm(lc_loop *l, session *s)
{
    unsigned lan = 0, up = 0;

    /* On the Hysteria2 plane there is no socket towards the node to arm — the loop watches the one
     * shared QUIC connection, once, on its own. Only the client side belongs to this session, and a
     * datagram session does not even have that. */
    if (s->hy_h != 0) {
        if (s->is_udp)
            return 0;
        if (s->st == ST_OPEN) {
            /* READING IS NOT THIS LOOP'S ANY MORE on this plane: the reader thread owns the client's
             * descriptor for reading and fills `to_up` itself. All that is left here is to tell it
             * there is room again, which it needs only if it had stopped for want of any. The write
             * side is untouched — the client is still written to from here.
             *
             * Under the plane's guard because the stage is: a build without Hysteria2 has no reader,
             * no stage and no way to reach this branch, since `s->hy_h` is zero for every session. */
#if LC_HYSTERIA
            lc_reader_rearm(&s->stage);
#endif
            if (q_pending(&s->to_lan) > 0)
                lan |= LC_EV_WRITE;
        }
        return lc_loop_mod(l, s->lan_fd, lan, &s->lan_tag) != 0 ? -1 : 0;
    }

    /* Between two attempts there is no upstream descriptor to arm at all — dial_failed closed it —
     * and the client's side is not on the loop until the tunnel opens. What wakes this session is the
     * clock, in sessions_expire. Handled before the switch because everything after it mods `up_fd`,
     * and -1 is not a descriptor lc_loop_mod will take. */
    if (s->st == ST_REDIAL)
        return 0;
    /* Nothing on the loop to arm: a request waiting on the pool has no upstream descriptor and its
     * client's is not registered until a pooled connection is bound to it (spare_bind), and a pooled
     * connection the node has closed is off the loop until a request takes it (spare_died). */
    if (s->st == ST_POOLWAIT || s->st == ST_HYWAIT || (s->st == ST_SPARE && s->spare_dead))
        return 0;

    switch (s->st) {
    case ST_REDIAL:
    case ST_POOLWAIT:
    case ST_HYWAIT:
        /* Answered above, before anything could reach `up_fd`. Listed rather than left to a default
         * so that -Wswitch keeps holding this switch to the whole enum — which is what made the
         * compiler point here the moment the state was added. */
        break;

    case ST_CONNECTING:
        /* Writability is how a non-blocking connect reports that it finished, whether it succeeded
         * or not. The client is not read from yet: whatever it sends waits in the kernel's receive
         * buffer, which is the right place for it until there is somewhere to forward it to.
         *
         * A dial to a name is its own descriptor, readable when its lookup or one of its connects
         * has something to say — see dial_turn. */
        up = s->dial != NULL ? LC_EV_READ : LC_EV_WRITE;
        break;

    case ST_HANDSHAKE:
        /* The same shape, and for the same reason: one thing is being written or one thing is being
         * waited for, and the client's own descriptor is not read from — there is nothing to forward
         * it to. */
        up = q_pending(&s->to_up) > 0 ? LC_EV_WRITE : LC_EV_READ;
        break;

    case ST_SPIDER:
        /* Nor in ST_SPIDER, where there never will be. The node's side is read while writes wait, as
         * the reference's readLoops read while its writers write — a writer x/net has stuck for good
         * (reality/fetch.c, spew) never stops waiting — until x/net has closed the connection, when
         * only its last writes are left to go. Not while a KeyUpdate's answer is owed: the readLoop
         * is then waiting on the write lock too — see node_key_update. */
        up = q_pending(&s->to_up) > 0 ? LC_EV_WRITE : 0u;
        /* The initial request turn runs before the socket is armed; after that the loop reads only
         * while TLS can accept records and no KeyUpdate response is owed. */
        if (!s->spider_end && !s->spider_peer_lost && s->ku_owed == 0u &&
            !s->spider_ku_pending && lc_spider_fetch_read_ready(s->fetch))
            up |= LC_EV_READ;
        break;

    case ST_SPARE:
        /* ⚠️ THE SAME RULE AS THE TWO ABOVE, AND WRITING "READ" HERE WAS A REAL BUG rather than a
         * tidier way to say the same thing.
         *
         * What reaches ST_SPARE still has the client's Finished IN THE QUEUE: the handshake machine
         * produces it, `to_up` holds it, and it goes out on the next writable event like everything
         * else. Arming read-only meant that event never came, so the spare sat with its own
         * Finished undelivered — and from the node that is a client that authenticated and then
         * went silent mid-handshake. The reference answers exactly that: its target-probe goroutine
         * closes the connection when the target's read ends while `isHandshakeComplete` is still
         * false (vendor/REALITY/tls.go:388-401), which on the stand was five seconds later.
         *
         * The symptom was one line of statistics — every spare `closed by the node`, none expired —
         * and nothing else. No test could have caught it: the record layer, the handshake and the
         * pool were all doing exactly what they were told. It took the reference server.
         *
         * Once the queue is empty this is a read watch, which is what the paragraph that stood here
         * described and remains true for the whole idle life of a spare: it is how the node closing
         * one — or sending a session ticket — is noticed while it still costs nothing, rather than
         * at the moment a person is waiting for the page it was going to carry. */
        up = q_pending(&s->to_up) > 0 ? LC_EV_WRITE : LC_EV_READ;
        break;

    case ST_OPEN:
        /* UP_WORST_PER_READ, not a round allowance — see the arithmetic where it is defined. The
         * read that completes the request carries the header in front of it, and none is taken while
         * the last one is still being written (up_n), or while a KeyUpdate's answer waits for room —
         * which the room asked for here already rules out, and is said anyway. */
        if (!s->lan_eof && s->up_n == 0u && s->ku_owed == 0u &&
            q_room(&s->to_up) >= (s->request_due ? UP_WORST_FIRST_WRITE : UP_WORST_PER_READ))
            lan |= LC_EV_READ;
        if (q_pending(&s->to_lan) > 0 || s->in_pipe > 0)
            lan |= LC_EV_WRITE;
        if (q_pending(&s->to_up) > 0)
            up |= LC_EV_WRITE;

        /* On the raw path the node is read only into an EMPTY pipe, as spliceDrain is only ever
         * entered with one (GOROOT/src/internal/poll/splice_linux.go:78-79): while the pipe holds
         * anything the node is not read, and the backpressure is the pipe's. See splice_direct.
         *
         * Nor while a KeyUpdate's answer is owed: the reference's reader is still inside
         * handleKeyUpdate, waiting for the write lock — see node_key_update. */
        if (!s->up_eof && s->ku_owed == 0u &&
            (!s->direct_in || (s->rx_len == 0u && q_pending(&s->to_lan) == 0u))) {
            if (s->direct_in && s->pipe_rd >= 0) {
                if (s->in_pipe == 0u)
                    up |= LC_EV_READ;
            } else if (s->direct_in) {
                if (q_room(&s->to_lan) > 0)
                    up |= LC_EV_READ;
            } else if (q_room(&s->to_lan) >= LC_REC_MAX_PLAINTEXT) {
                up |= LC_EV_READ;
            }
        }
        break;
    }

    /* The client side of a datagram session is a shared socket the loop already watches, so only
     * the tunnel side is this session's to arm. A spare has no client side at all yet — the same
     * shape for a different reason, and the descriptor is -1, which lc_loop_mod would refuse. And a
     * stream's client side is not on the loop until the tunnel is open: see start_tunnel. */
    if (s->is_udp || s->lan_fd < 0 || s->st != ST_OPEN)
        return lc_loop_mod(l, s->up_fd, up, &s->up_tag) != 0 ? -1 : 0;

    if (!s->lan_on_loop) {
        if (lc_loop_add(l, s->lan_fd, lan, &s->lan_tag) != 0)
            return -1;
        s->lan_on_loop = 1;
    } else if (lc_loop_mod(l, s->lan_fd, lan, &s->lan_tag) != 0) {
        return -1;
    }
    /* ERR/HUP are reported even with a zero interest mask. A raw reader whose
     * preceding Write is blocked must not observe them yet or spin on them.
     * Preserve an active uplink writer: its own failure can still end the pair. */
    if (s->direct_in && up == 0u &&
        (s->up_eof || s->rx_len > 0u || q_pending(&s->to_lan) > 0u)) {
        if (!s->raw_poll_paused) {
            if (lc_loop_del(l, s->up_fd) != 0)
                return -1;
            s->raw_poll_paused = 1;
        }
        return 0;
    }
    if (s->raw_poll_paused) {
        if (lc_loop_add(l, s->up_fd, up, &s->up_tag) != 0)
            return -1;
        s->raw_poll_paused = 0;
        return 0;
    }
    return lc_loop_mod(l, s->up_fd, up, &s->up_tag) != 0 ? -1 : 0;
}

/* Moves the raw stream from the node to the client without it passing through this process — the
 * way the reference moves it. Xray's copy is one line, `w, err := tc.ReadFrom(readerConn)`
 * (vendor/Xray-core/proxy/proxy.go:778), and everything under it is Go's: TCPConn.ReadFrom takes
 * internal/poll's Splice (GOROOT/src/internal/poll/splice_linux.go:33-74), which does, in a loop:
 *
 *   drain   ONE splice from the node's socket into the pipe, of up to maxSpliceSize = 1 MiB
 *           (:41-45, :86-112), and only into an EMPTY pipe — "when entering spliceDrain, the pipe
 *           is empty" (:78-79);
 *   pump    all of it from the pipe to the client, round again after every partial write until
 *           nothing is left (:127-162);
 *
 * and only then reads the node again (:40). EAGAIN from the drain waits for the node to be readable
 * (:106-107) — the node's read is armed here only while the pipe is empty, see session_rearm — and
 * EAGAIN from the pump waits for the client to be writable (:155-156). The flags are
 * spliceNonblock alone (:19, :99, :141).
 *
 * ⚠️ WHAT THIS DID BEFORE 2026-09-24, and was never held to the reference: a 16 KiB pipe, ONE splice
 * per wake-up into whatever room the pipe had left, the node's read armed while the pipe was not
 * full, and the pump interleaved with it. Chosen at the start for memory and so that a fast
 * download could not starve the other connections — and never compared, because the reference's
 * half of it is not in Xray at all but in Go's runtime, which nobody read. On the AX3000T it was
 * the reading pattern the node sees: Xray left up to 4.2 MB unread in its socket to the node, this
 * never more than 0.5 MB, and took 8–13 % of a core where Xray took 5–7 %. The starvation it was
 * guarding against does not come: the loop below ends as soon as the node's socket is empty, which
 * on any real link is after a drain or two, since a drain takes everything that has arrived.
 *
 * Returns -1 only for an error that ends the connection. */
static int splice_direct(session *s, int readable)
{
    (void)readable; /* the drain is tried whenever the pipe is empty, as spliceDrain does */
    for (;;) {
        if (s->in_pipe == 0u) {
            if (s->up_eof)
                return 0;
            ssize_t n = splice(s->up_fd, NULL, s->pipe_wr, NULL, SPLICE_MAX, SPLICE_F_NONBLOCK);
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return 0; /* spliceDrain's waitRead */
                return -1;
            }
            if (n == 0) {
                s->up_eof = 1; /* "If spliceDrain returns (0, nil), src is at EOF." (:85) */
                return 0;
            }
            stats.direct_bytes += (uint64_t)n;
            s->in_pipe = (size_t)n;
            /* NOT ACTIVITY, AND THAT IS THE REFERENCE, NOT AN OVERSIGHT.
             *
             * Once Xray's copier goes to splice it moves the connection's timer to a day and makes
             * no Update for the bytes the kernel carries (vendor/Xray-core/proxy/proxy.go:770-790):
             * the process never sees them. What this refreshed instead was a one-second deadline armed
             * at the client's half-close, on the reasoning that the reference's timer is refreshed by
             * every chunk — true of its copy loop, and not of its splice. In the reference a client that
             * half-closes BEFORE the splice starts has its one second replaced by the day, and one that
             * half-closes during it has its download ended one to two seconds later. Both are what
             * act_set and the day now do here. */
        }

        /* The pump waits on the queue, which is ours and not the reference's shape: the queue still
         * holds what arrived in the same record as the announcement, and letting the pipe overtake
         * it would deliver the stream out of order. The drain above has already filled the pipe,
         * once, which is all spliceDrain would have done. */
        if (q_pending(&s->to_lan) != 0)
            return 0;
        while (s->in_pipe > 0u) {
            ssize_t n = splice(s->pipe_rd, NULL, s->lan_fd, NULL, s->in_pipe, SPLICE_F_NONBLOCK);
            if (n > 0) {
                s->in_pipe -= (size_t)n;
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                return 0; /* splicePump's waitWrite: the client is behind */
            return -1;    /* including 0, which "should never be observed" (:145-146) */
        }
    }
}

/* The same job without a pipe, for when one could not be had.
 *
 * Slower — the bytes come through this process — but still free of the record layer and the second
 * decryption, which is where most of the cost was. Running out of descriptors should make a
 * connection slower, not kill it. */
static int copy_direct(session *s, int readable)
{
    if (!readable)
        return 0;

    size_t room = q_room(&s->to_lan);
    if (room == 0)
        return 0;

    /* Read into the queue itself rather than into a buffer here and then copy. The call above has
     * just established that there are `room` free bytes at buf + len — q_room is also what resets a
     * queue that has been fully drained — and the read is bounded by that, so what q_push would do
     * with the result is exactly a memcpy to that address and len += n, without ever reaching its
     * compaction path. Only the second half of that is left. Nothing between the two calls touches
     * the queue, so the room measured is still the room written into. */
    size_t  want = room < READ_CHUNK ? room : READ_CHUNK;
    ssize_t got = read(s->up_fd, s->to_lan.buf + s->to_lan.len, want);
    /* No refresh here either: the reference splices where this copies for want of a pipe, and its
     * splice makes none. */
    if (got > 0) {
        stats.copied_bytes += (uint64_t)got;
        s->to_lan.len += (size_t)got;
        return q_flush(&s->to_lan, s->lan_fd) != 0 ? -1 : 0;
    }
    if (got == 0) {
        s->up_eof = 1;
        return 0;
    }
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
}

/* Whichever of the two the connection ended up with. */
static int direct_pump(session *s, int readable)
{
    /* The returned Vision MultiBuffer finishes before the next raw Read, even
     * when a partial Flush has freed queue room. Arm only the pending writer
     * until then; a readable node must not spin or overtake these older bytes. */
    if (s->rx_len > 0u && raw_carry(s) != 0)
        return -1;
    if (s->rx_len > 0u || q_pending(&s->to_lan) > 0u)
        return 0;
    return s->pipe_rd >= 0 ? splice_direct(s, readable) : copy_direct(s, readable);
}

/* Everything a fresh session needs between "we know where it is going" and "the loop owns it".
 *
 * Nothing here waits. The connection is started, the ClientHello is built and queued, and the loop
 * carries both to completion — which is what stops one new connection from holding up every other
 * one on the device for a round trip. Shared by the stream and datagram paths so that the two
 * cannot drift into different ideas of how a tunnel begins. */
/* Declared rather than moved: the dial is the tail of start_tunnel and reads as its tail, and there
 * is a second caller only because the reference dials more than once. See DIAL_TRIES. */
/* The node given by NAME, looked up per dial (net/dial.h); NULL when it is given as an address,
 * which main has then parsed into the lc_resolved every dial is handed. */
static const char *node_name;
static uint16_t    node_name_port;

static int dial_node(lc_loop *loop, session *s, const uint8_t *table, size_t table_len,
                     const char *sni, const lc_reality_config *reality,
                     const lc_resolved *node_addr);
static int dial_failed(lc_loop *l, session *s);

static int start_tunnel(lc_loop *loop, session *s, const char *host, uint16_t port,
                        const uint8_t *uuid, const char *flow,
                        const uint8_t *table, size_t table_len, const char *sni,
                        const lc_reality_config *reality, const lc_resolved *node_addr)
{
    /* The same predicate the request header uses, so the two cannot come apart: one of them asked
     * "is it empty" and the other "is it exactly Vision", and a flow that was neither made them
     * disagree. Unknown flows are refused at the command line, so this only ever sees 0 or 1. */
    s->use_vision = lc_vless_flow(flow) == 1;

    lc_vision_init(&s->vision, uuid);

    snprintf(s->target_host, sizeof s->target_host, "%s", host);
    s->target_port = port;
    s->uuid = uuid;
    s->flow = flow;
    s->sni = sni;
    s->began_ms = lc_now_ms();
    s->dial_try = 0;

    /* UP TO FIVE ATTEMPTS, BECAUSE THE REFERENCE MAKES FIVE, and every failure of one earns the next
     * — the rules, the waits and the citations live at DIAL_TRIES.
     *
     * Every connection on the device goes through this lifecycle: a session whose attempt fails keeps
     * its LAN socket, drops the upstream descriptor and the spent ClientHello, and comes back through
     * ST_REDIAL with a fresh one. A SPARE IS REFUSED A REDIAL and that is not an omission — the
     * reference's retry sits on the outbound's own dial, not on its pre-connect goroutine, which
     * `continue`s straight back into a fresh dial with no wait at all
     * (vendor/Xray-core/proxy/vless/outbound/outbound.go:165-168). A failed pooled dial is closed, and
     * pool_tick dials anew on the next turn.
     *
     * ⚠️ WHAT THIS ROUTER'S FAILURES HAVE BEEN IS HANGS, and retrying does not shorten those: read on
     * the live box over five and a half hours, 3681 opens gave `0 dials failed outright` and every
     * give-up was the node accepting us and then saying nothing while we read ServerHello. The
     * reference waits on such a handshake without a clock, and so does this now; `gave up` in the
     * summary counts connects that ran out of time and requests that ran out of attempts, and a hang
     * is neither. */
    /* A first attempt that cannot even begin is a failed attempt like any other. */
    if (dial_node(loop, s, table, table_len, sni, reality, node_addr) != 0 && dial_failed(loop, s) != 0)
        return -1;

    /* ⚠️ THE CLIENT'S SOCKET IS NOT WATCHED WHILE THE NODE IS DIALLED, which is the reference: dokodemo
     * hands its reader to the outbound through DispatchLink and does not read it itself
     * (vendor/Xray-core/proxy/dokodemo/dokodemo.go:152-199), and the outbound reads it only once Dial
     * has returned. A client that resets or closes during the dial goes unnoticed until the request
     * reads, and the dial — every attempt of it — goes on. It is registered when the tunnel opens; see
     * session_rearm. */
    return session_rearm(loop, s);
}

/* One attempt at the node: the connect, the ClientHello built while it is in the air, and the
 * descriptor handed to the loop. Separate from start_tunnel because there may be up to DIAL_TRIES
 * of these for one session while everything above that call happens once.
 *
 * A fresh ClientHello per attempt rather than the spent one reused: uTLS draws GREASE, the padding
 * length and the ECH candidate anew for every hello, so two attempts from this client look like two
 * connections from one browser — which is what the node sees from a browser anyway. */
static int dial_node(lc_loop *loop, session *s, const uint8_t *table, size_t table_len,
                     const char *sni, const lc_reality_config *reality,
                     const lc_resolved *node_addr)
{
    s->dial_try++;
    s->st = ST_CONNECTING;
    s->deadline = lc_now_ms() + CONNECT_ATTEMPT_MS;
    /* A new attempt is a new tls.Conn, and its record-size schedule starts from nothing. */
    s->tls_records_sent = 0;
    s->tls_bytes_sent = 0;

    /* A NODE GIVEN BY NAME IS LOOKED UP FOR THIS ATTEMPT, as the reference looks it up for every
     * dial (vendor/Xray-core/transport/internet/system_dialer.go:171), and its sixteen seconds cover
     * the lookup — net/dial.h has the whole of Go's dial it follows. The lookup is on a thread: on the
     * loop thread, where getaddrinfo once ran for every accepted connection, it stalled every other
     * session on the device for the length of one lookup. */
    if (node_name != NULL) {
        s->dial = lc_dial_start(node_name, node_name_port, lc_now_ms(), CONNECT_ATTEMPT_MS);
        if (s->dial == NULL) {
            note("cannot start a dial to the node: %s", strerror(errno));
            return -1;
        }
        s->up_fd = lc_dial_fd(s->dial);
        s->deadline = lc_dial_wake(s->dial);
    }
    /* A node given as an address, parsed before the loop existed: one address, one connect, which is
     * what Go's dial comes to for a literal. */
    else if ((s->up_fd = lc_connect_begin(node_addr)) < 0) {
        /* RUNNING OUT OF DESCRIPTORS IS NOT THE NODE BEING UNREACHABLE, and it was once reported as
         * one — with a line blaming the network and a device-wide backoff behind it. EMFILE and
         * ENFILE are local: the node was never asked and nothing about the path changed. The line
         * names what happened; the attempt fails like any other and dial_failed decides what
         * follows, which is the reference's retry — its Dial returns this as it returns any error. */
        if (errno == EMFILE || errno == ENFILE) {
            note("no descriptor left for a connection to the node: a local limit, not the path");
            return -1;
        }
        stats.dial_failed++;
        note("cannot reach the node: no address of it could be opened at all");
        return -1;
    }

    /* SAID ONCE, AND ONLY SAID. The stamp goes into the REALITY payload whatever it is, because the
     * reference stamps time.Now().Unix() and knows no other rule; refusing on a clock we judged too
     * wrong would be a rule of our own, which is the thing this tree keeps removing.
     *
     * But a node that DOES set maxTimeDiff answers a bad stamp the way REALITY answers everything —
     * by serving the site it hides behind — and that is indistinguishable, from here, from a wrong
     * key, a wrong short id, a middlebox rewriting the hello, or the node being gone. This line is
     * the one of those five that can be ruled out for free, and it is worth ruling out on a router:
     * OpenWrt boots with the clock at the firmware's build date and stays there until NTP lands,
     * which on a device whose route to NTP goes through this tunnel is a chicken-and-egg.
     *
     * The number is a diagnostic threshold and nothing on the wire depends on it: 2020-01-01, below
     * which no machine running this software is telling the truth about the date. */
    uint32_t stamp = (uint32_t)time(NULL);
    static int clock_said;
    if (stamp < 1577836800u && !clock_said) {
        clock_said = 1;
        note("the clock reads %lu, which is before this software existed — if the node sets "
             "maxTimeDiff it will refuse us, and its refusal is silence",
             (unsigned long)stamp);
    }

    lc_client_config cfg = {
        .table = table, .table_len = table_len, .sni = sni,
        .use_reality = 1, .reality = reality, .unix_time = stamp,
    };
    s->hs = lc_client_hs_new(&cfg);
    gcemu_handshake(); /* what the reference allocates for one, succeeded or not — see gcemu */
    if (s->hs == NULL)
        return -1;

    /* ⚠️ THE HELLO IS BUILT NOW, WHILE THE TCP HANDSHAKE IS STILL IN THE AIR, and that is worth a
     * paragraph because it is free and it was not free before.
     *
     * `lc_client_hs_new` only allocates. Everything the first message costs — the hybrid keypair and
     * the REALITY stamp on top of it — happens in phase_hello, which used to run on the first
     * lc_client_hs_step, and that call sits where the loop learns the socket is writable. So the
     * order was: start connect, wait a whole round trip doing nothing, then compute, then send.
     *
     * On a router the computing half is not small. Measured with test/bench/bench-kex on the target
     * box (MIPS 1004Kc, 880 MHz): lc_hybrid_keygen 22.54 ms — of which ML-KEM-768 is 1.42 and the
     * X25519 half was 21, while mbedTLS reached Curve25519 through its generic ECP code; since
     * 2026-09-20 X25519 is this client's own field arithmetic, 16.40 ms per scalar multiplication
     * down to 5.30 on that box (src/tls/x25519.h). The round
     * trip it now hides behind is 64 ms to the nearest node and 175 to the far one, so the whole of
     * it disappears from the wait either way.
     *
     * Nothing about the message changes — same table, same draws, same stamp — so this is invisible
     * to anything watching. It is only WHEN the arithmetic happens.
     *
     * A refusal here needs no alert and gets none: phase_hello's failures are the ones hs_alert
     * names as deliberately silent, because nothing has been written to anybody yet. */
    if (lc_client_hs_step(s->hs, &s->cl) == LC_HS_FAILED) {
        note("could not build the ClientHello: %s", lc_client_hs_error(s->hs));
        return -1;
    }

    if (lc_loop_add(loop, s->up_fd, s->dial != NULL ? LC_EV_READ : LC_EV_WRITE, &s->up_tag) != 0)
        return -1;
    return 0;
}

/* ONE ATTEMPT HAS FAILED, WHATEVER FAILED IN IT: the connect, the handshake, the node closing the
 * connection, or the node answering as a stranger. Returns 0 when the session is now in ST_REDIAL and
 * the caller must NOT close it; -1 when it is the caller's to end — a pooled dial, which the
 * reference's pre-connect goroutine simply makes again (`continue`,
 * vendor/Xray-core/proxy/vless/outbound/outbound.go:165-168), so pool_tick does.
 *
 * The wait is the retry's: (attempt - 1) × 200 ms, slept after the fifth attempt as after the others.
 * When the fifth is spent the session waits that out in ST_REDIAL too, and sessions_expire closes it
 * then — the reference's request failing, "failed to find an available destination", 800 ms after
 * its last dial. See DIAL_TRIES.
 *
 * The upstream half goes and the client's half stays: the client does not know the dial failed, and
 * in the reference nothing tells it until the request gives up. */
static int dial_failed(lc_loop *l, session *s)
{
    if (s->closing || s->is_spare || s->hy_h != 0 || s->dial_try == 0u)
        return -1;

    uint64_t at = lc_now_ms() + (uint64_t)(s->dial_try - 1u) * DIAL_STEP_MS;

    /* Deregistered before the close for the reason session_close gives at the same pair of calls:
     * only so that a descriptor about to go generates no further events. */
    dial_drop(l, s);
    if (s->up_fd >= 0) {
        lc_loop_del(l, s->up_fd);
        if (s->gc_park)
            gcemu_park(s->up_fd); /* a failed handshake's: the collector's to close — see gcemu */
        else
            close(s->up_fd);
        s->up_fd = -1;
    }
    s->gc_park = 0;
    /* The spent handshake and its keys. A fresh hello is drawn for the next attempt — see the note
     * above dial_node for why that is the faithful thing rather than the convenient one — and the
     * record keys are freed rather than overwritten because they hold cipher contexts. */
    if (s->hs != NULL) {
        lc_client_hs_free(s->hs);
        s->hs = NULL;
    }
    lc_client_free(&s->cl);
    memset(&s->cl, 0, sizeof s->cl);
    lc_post_free(&s->post);
    s->post.useless = 0;
    s->post.tls12 = 0;
    s->ku_owed = 0;
    /* Whatever of the old attempt never left the queue. It belongs to a socket that no longer
     * exists. */
    s->to_up.len = s->to_up.off = 0;
    s->rx_len = 0;
    /* And the reference's buffer with it: a new attempt is a new tls.Conn. */
    memset(&s->rin, 0, sizeof s->rin);
    s->hs_fed = 0;
    s->rin_ahead = 0;

    s->redial_at = at;
    s->deadline = 0;
    s->st = ST_REDIAL;
    if (s->dial_try < DIAL_TRIES)
        stats.dial_retried++;
    return 0;
}

/* ---- tunnels dialled ahead of need -------------------------------------------------------- */

/* WHAT A PERSON WAITS FOR WHEN THEY OPEN A PAGE, AND WHY NONE OF IT IS ABOUT THE PAGE.
 *
 * Opening one proxied stream costs two round trips to the node plus this CPU's share of the
 * asymmetric work, and on the target box that share is not small: lc_hybrid_shared 24.02 ms and an
 * Ed25519 verify at 79.76 ms, measured with test/bench/bench-kex on MIPS 1004Kc at 880 MHz. Against
 * a 64 ms node that is roughly 230 ms before the first byte of the request can leave, and about 430
 * against a 175 ms one. NOTHING IN IT DEPENDS ON THE DESTINATION: the VLESS request that names the
 * host is written after the handshake, so a tunnel opened for nobody in particular is the same
 * tunnel as one opened for a specific site.
 *
 * So it can be paid in advance. That is what these are: connections carried through the whole
 * REALITY handshake and then held, so that the next stream a device on the LAN asks for starts by
 * writing its request rather than by dialling.
 *
 * ⚠️ THIS IS THE REFERENCE'S OWN FEATURE, which is the only reason it is allowed here at all. Xray's
 * VLESS outbound keeps a pre-connect pool — `testpre` goroutines each dialling, handing the
 * connection to an unbuffered channel and sleeping 200 ms
 * (vendor/Xray-core/proxy/vless/outbound/outbound.go:157-186). An idle authenticated REALITY
 * connection from a client that has said nothing yet is therefore a shape upstream produces, not
 * one invented here. It is off by default there — `testpre` is a per-account field that defaults to
 * zero — and off by default here.
 *
 * ⚠️ WHAT UPSTREAM'S LOOP DOES, READ LINE BY LINE — an earlier version of this note got it wrong.
 * It said upstream "redials forever whether or not anything ever takes one" and argued from that
 * about beacons. It does not: the channel is unbuffered (vless/outbound/outbound.go:159), so the send at :170
 * blocks until a request takes the connection, and an idle Xray holds its `testpre` connections and
 * dials nothing more. Upstream, in full:
 *   - the pool is created inside Process, on the FIRST REQUEST (`h.initpre.Do`, :157-158) — the
 *     reference dials nothing before something asks;
 *   - `testpre` goroutines per outbound, each: dial; on failure log and dial again at once
 *     (:165-168); hand the connection over; sleep 200 ms; dial the next (:170-171);
 *   - a connection is stamped to expire two minutes after its dial (:170), and only the taker reads
 *     the stamp: an expired one is closed and the next taken (:177-186).
 *
 * ⚠️ AND THIS POOL IS THAT LOOP, ON AN EVENT LOOP INSTEAD OF GOROUTINES. It used to be a pool of
 * this client's own design — primed at startup, on by default, 25-35 s of life, refilled on use with
 * a debt for what expired, a failed dial ending the round, and a fresh dial for a request whose warm
 * tunnel had died — and every one of those was a divergence. What is left:
 *   - `-P N` is `testpre`, and the default is the reference's zero (infra/conf/vless.go:255): off;
 *   - nothing is dialled until the first request (pool_start); from then on up to N connections are
 *     being dialled or waiting to be taken, and a dialler whose connection was handed over sleeps
 *     SPARE_SLEEP_MS before dialling again (pool_tick);
 *   - a failed dial is dialled again on the next turn of the loop, without the retry's waits that a
 *     request's own dial has (dial_failed);
 *   - with the pool on, EVERY request takes a pooled connection and none dials for itself: one that
 *     finds nothing ready waits (ST_POOLWAIT), oldest first;
 *   - the taker reads the stamp and nothing else does: an expired connection is closed and the next
 *     one taken (spare_take), and a connection the node has closed stays in the pool until then
 *     (spare_died) — so a request can be handed a dead one and fail, exactly as upstream's does.
 *
 * ⚠️ ONE THING IS STILL THIS CLIENT'S, AND IT IS THE PROCESS MODEL, NOT THE POOL. Xray is one process;
 * lc-tunnel with `-w` is several, sharing the listeners and nothing else, so each worker runs its own
 * pool of N. A router with `-w 4 -P 1` holds up to four pooled connections where one Xray would hold
 * one. */
static struct {
    /* `testpre`: how many connections the pool keeps being dialled or waiting. Zero — the
     * reference's default — turns the whole thing off. */
    unsigned want;

    /* Whether a request has arrived yet. The reference creates its pool inside Process, on the first
     * request (`h.initpre.Do`, vless/outbound/outbound.go:157-158), and dials nothing before. */
    int started;

    /* The diallers that have handed a connection over and are in their 200 ms sleep, as the moment
     * each wakes. A dialler is either dialling, waiting with a connection (both counted by
     * spare_count), or here. */
    uint64_t wake[POOL_MAX];
    unsigned sleeping;

    /* Set when a dial could not even begin — no descriptor, no memory for the session. The reference's
     * dialler goes straight back to Dial; here that is the next turn of the loop, so the loop must not
     * sleep in between (hy_wait). */
    int retry_now;

    /* The order requests started waiting in. */
    uint64_t seq;

    /* Everything a dial needs, captured once in main. A refill happens deep inside the loop, far
     * from the command line, and threading seven arguments through every call site that might
     * trigger one is how the two ideas of "how a tunnel begins" drift apart — which is the exact
     * fault start_tunnel exists to prevent. */
    const uint8_t           *uuid;
    const char              *flow;
    const uint8_t           *table;
    size_t                   table_len;
    const char              *sni;
    const lc_reality_config *reality;
    const lc_resolved       *node;
} spare = { .want = 0u };

/* Whether requests on this plane go through the pool at all. */
static int pool_on(void)
{
    return spare.want > 0u && spare.node != NULL;
}

/* Pooled connections being dialled or waiting to be taken — one per dialler that is not asleep. */
static unsigned spare_count(void)
{
    unsigned n = 0;
    for (unsigned i = 0; i < sessions_cap; i++) {
        session *s = sessions[i];
        if (s != NULL && !s->closing && s->is_spare)
            n++;
    }
    return n;
}

/* Declared rather than moved: it binds a pooled connection to a request, and reads best next to the
 * handshake state a pooled connection stops at. */
static int spare_bind(lc_loop *loop, session *s, const char *host, uint16_t port);

/* The first request starts the pool — `h.initpre.Do` inside Process (vless/outbound/outbound.go:157-158). */
static void pool_start(void)
{
    spare.started = 1;
}

/* A dialler has handed its connection over — to a request, or to a taker that found it expired — and
 * sleeps before it dials the next: `time.Sleep(time.Millisecond * 200)` right after the send
 * (vless/outbound/outbound.go:170-171). At most `want` diallers exist, so the array cannot overflow; the bound is
 * checked anyway rather than trusted. */
static void pool_sleep(void)
{
    if (spare.sleeping < sizeof spare.wake / sizeof spare.wake[0])
        spare.wake[spare.sleeping++] = lc_now_ms() + SPARE_SLEEP_MS;
}

/* A pooled connection the node closed, reset, or spoke on out of turn while it waited.
 *
 * The reference does not notice any of that: its connection sits in the channel unread until a request
 * takes it, and the request is what finds out, by failing. So this one stays in the pool as well —
 * counted, taken off the loop so that a socket at end of file does not wake it on every turn, and left
 * open, as an unread Go connection is, until a request takes it or finds it expired. */
static void spare_died(lc_loop *loop, session *s)
{
    if (s->spare_dead)
        return;
    stats.spare_lost++;
    lc_loop_del(loop, s->up_fd);
    s->spare_dead = 1;
}

/* The reference's taker (vless/outbound/outbound.go:177-186): the connection that has waited longest, unless its two
 * minutes are over — then it is closed, its dialler goes to sleep as for any hand-over, and the next one
 * is looked at. NULL when nothing is waiting to be taken. "Waited longest" is the order of an unbuffered
 * Go channel, which hands a receiver to the sender that blocked first; that sender is the connection
 * whose dial finished first, and so the one with the earliest stamp. */
static session *spare_take(lc_loop *loop)
{
    uint64_t now = lc_now_ms();
    for (;;) {
        session *best = NULL;
        for (unsigned i = 0; i < sessions_cap; i++) {
            session *s = sessions[i];
            if (s == NULL || s->closing || s->st != ST_SPARE || !s->is_spare)
                continue;
            if (best == NULL || s->deadline < best->deadline)
                best = s;
        }
        if (best == NULL)
            return NULL;
        pool_sleep();
        if (now >= best->deadline) {
            stats.spare_expired++;
            session_close(loop, best);
            continue;
        }
        best->is_spare = 0;
        stats.spare_taken++;
        return best;
    }
}

/* A request with the pool on. It waits for a pooled connection — `connTime := <-h.preConns`
 * (vless/outbound/outbound.go:177) — and never dials for itself. Its client and destination are already in place;
 * pool_tick binds the next connection to it. The wait has no clock and does not watch the client,
 * as the receive in the reference has none and does not. */
static int pool_wait(session *s, const char *host, uint16_t port)
{
    pool_start();
    snprintf(s->target_host, sizeof s->target_host, "%s", host);
    s->target_port = port;
    s->began_ms = lc_now_ms();
    s->pool_seq = ++spare.seq;
    s->st = ST_POOLWAIT;
    return 0;
}

/* Binds a pooled connection to the request that has waited longest. The client side moves from the
 * waiting session onto the connection's — the descriptor, and for a datagram session the peer, its id,
 * the destination table and whatever it said while it waited — and the empty shell is closed.
 *
 * A request that cannot then be carried fails, and the connection is spent with it. That is the
 * reference once `conn` is in hand: `defer conn.Close()` (vless/outbound/outbound.go:201), and any error from there on
 * goes back to the inbound — there is no second dial for a request whose pooled connection was dead. */
static void pool_serve(lc_loop *loop, session *s, session *w)
{
    char     host[sizeof w->target_host];
    uint16_t port = w->target_port;
    snprintf(host, sizeof host, "%s", w->target_host);

    s->lan_fd = w->lan_fd;
    w->lan_fd = -1;
    s->is_udp = w->is_udp;
    s->peer = w->peer;
    s->peer_len = w->peer_len;
    memcpy(s->global_id, w->global_id, sizeof s->global_id);
    s->idle_deadline = w->idle_deadline;
    s->udp_seen_s = w->udp_seen_s;
    /* The table's size with it. It was left behind, so a served datagram session had room for
     * none: the first address it had fitted, and every new one after it took that one's place and
     * closed its reply socket — one destination at a time, with the pool on. */
    s->dests = w->dests;
    s->dest_count = w->dest_count;
    s->dest_cap = w->dest_cap;
    w->dests = NULL;
    w->dest_count = w->dest_cap = 0;
    s->pend_q = w->pend_q;
    w->pend_q = NULL;
    /* What the person waited is measured from when they arrived, not from when a connection came. */
    s->began_ms = w->began_ms;
    session_close(loop, w);

    if (spare_bind(loop, s, host, port) != 0) {
        /* The one refusal that is a rule rather than a failure has a counter of its own and no line. */
        if (!udp443_refused(s)) {
            if (log_per_connection())
                note("the pooled connection for %s:%u would not carry the request", host, port);
            else
                note("a pooled connection would not carry the request");
        }
        session_close(loop, s);
    }
}

/* The reference's diallers and its channel, one turn of the loop at a time.
 *
 * First, what is ready goes to who is waiting, oldest to oldest. Then every dialler whose sleep is over,
 * and every one whose connection failed, dials again — until `want` connections are being dialled or
 * are waiting to be taken. A dial that fails once it is under way has closed its session, so the count
 * comes up short and the dial is simply made again here, on the next turn: that is the reference's
 * `continue` (vless/outbound/outbound.go:165-168). One that cannot even begin sets retry_now, so the loop does not
 * sleep before the next turn.
 *
 * ⚠️ EVERY ONE OF THESE DIALS COSTS THE NODE A HANDSHAKE WITH THE COVER SITE, whether the connection is
 * ever used or not. The reference server dials `dest` as the first statement of Server(), before it
 * reads the ClientHello (vendor/REALITY/tls.go:169), because it needs the genuine certificate to mirror.
 * Counted at the node with conntrack on 2026-08-30 under this client's previous pool: 232 new
 * connections a minute to www.avito.ru from one address, nearly all of them finishing a handshake and
 * closing without a request. That is the price of `testpre` in the reference as much as here.
 *
 * The one guard that is not the reference's is the session table's: a pooled connection is never the
 * one that takes the last slots a request would need, because the table is a fixed array here and Go
 * has no such limit to protect. Eight, because a browser opens a page with fifteen at once. */
static void pool_tick(lc_loop *loop)
{
    if (!spare.started)
        return;

    for (;;) {
        session *w = NULL;
        for (unsigned i = 0; i < sessions_cap; i++) {
            session *c = sessions[i];
            if (c != NULL && !c->closing && c->st == ST_POOLWAIT &&
                (w == NULL || c->pool_seq < w->pool_seq))
                w = c;
        }
        if (w == NULL)
            break;
        session *s = spare_take(loop);
        if (s == NULL)
            break;
        pool_serve(loop, s, w);
    }

    uint64_t now = lc_now_ms();
    for (unsigned i = 0; i < spare.sleeping;) {
        if (now >= spare.wake[i])
            spare.wake[i] = spare.wake[--spare.sleeping];
        else
            i++;
    }

    spare.retry_now = 0;
    while (spare_count() + spare.sleeping < spare.want) {
        session *s = session_new();
        if (s == NULL)
            return;
        s->is_spare = 1;
        stats.spare_dialled++;
        /* No destination, and start_tunnel needs none: everything it does — the connect, the keypair,
         * the hello — is the same whatever the traffic turns out to be. */
        if (start_tunnel(loop, s, "", 0, spare.uuid, spare.flow, spare.table, spare.table_len,
                         spare.sni, spare.reality, spare.node) != 0) {
            session_close(loop, s);
            spare.retry_now = 1;
            return;
        }
    }
}

/* Gives a pooled connection its destination and its client, which is everything start_tunnel would
 * still have to do at this point. From here on the session is an ordinary open one.
 *
 * pool_serve has already put the client side in place — lan_fd, and for a datagram session is_udp,
 * the peer and the destination table — and the moment the person arrived. */
static int spare_bind(lc_loop *loop, session *s, const char *host, uint16_t port)
{
    /* A connection the node closed while it waited goes back on the loop, and the request is written
     * on it all the same: that is how the reference's request finds out, and how this one does. */
    if (s->spare_dead) {
        if (lc_loop_add(loop, s->up_fd, 0, &s->up_tag) != 0)
            return -1;
        s->spare_dead = 0;
    }

    snprintf(s->target_host, sizeof s->target_host, "%s", host);
    s->target_port = port;
    s->deadline = 0;
    s->st = ST_OPEN;

    note_open_wait(s);
    note_opened(s);

    /* ⚠️ AND WHAT THE CLIENT ALREADY SAID GOES OUT, which this once did not do — so with a spare in
     * hand the first datagram of every UDP session was swallowed.
     *
     * The UDP listener stores the datagram before it opens anything (`pend_put` at the take), because
     * at that moment there is no stream to write it to. A spare skips the whole handshake and arrives
     * here — with a stream and with the datagram still pending. Measured against a real Xray 26.7.28
     * on the local stand when this path forgot it: `chunks out 1 (37 bytes)`, the request header
     * alone, then silence and a resolver timing out; with `-P 0` the same command answered.
     *
     * The request is the same call the dialling path makes, which is what keeps the two from
     * drifting apart again: request_start writes the header with the client's first bytes or first
     * datagram — or, with the pool, where the client arrived a moment ago, waits for them as the
     * reference does. */
    if (request_start(s) != 0)
        return -1;

    return session_rearm(loop, s);
}

/* What a spare's socket may say while nobody is using it, and what it may not.
 *
 * A REALITY node speaks after its Finished, before anybody has asked it anything: empty records
 * in the lengths of its target's session tickets, the one in its first flight and those after the
 * client's Finished (vendor/REALITY/conn.go:567-571, vendor/REALITY/tls.go:419-435) — it runs
 * with SessionTicketsDisabled, so no real ticket. They are read here, through the same
 * node_record the stream uses, because an unread socket eventually fills.
 *
 * Reading them early changes nothing the node can see: Go leaves them in the kernel until the first
 * Read after the request, and the bytes and their acknowledgements are the same either way.
 *
 * Anything ELSE is the connection dying while it waits, and the caller hands it to spare_died. Real
 * application data before we have sent a VLESS request is the node saying something no VLESS inbound
 * says; an alert is the node closing; end of file is the node having closed already. What the
 * reference refuses is refused with its alert, and SOONER than it would be: the reference reads
 * nothing until the request has gone. Only a record no Go server sends — or one written into the
 * stream by somebody else — meets that difference. */
static int spare_records(session *s)
{
    for (;;) {
        if (s->rx_len < LC_REC_HEADER)
            return 0;
        if (node_header(s, s->rx) != 0)
            return -1;
        size_t whole = node_want(s);
        if (s->rx_len < whole)
            return 0;

        size_t  plain_len = 0;
        uint8_t inner = 0;
        int     rc = node_open(s, s->rx, whole, scratch.plain, sizeof scratch.plain, &plain_len,
                               &inner);
        rx_take(s, whole);
        if (rc != 0)
            return -1;
        /* Taken as the stream takes it — see node_record — so a ticket split across records, and
         * the count of records that carried nothing, go on where the stream picks them up. */
        rc = node_record(s, scratch.plain, plain_len, inner);
        /* Wiped for the same reason every other opened record is: the buffer is shared by every
         * connection on the device. A ticket is not the user's traffic, but the rule that makes the
         * sharing safe is "whatever was opened here is gone before the next caller", and a path that
         * quietly exempts itself is how that stops being true. */
        lc_wipe(scratch.plain, plain_len);

        /* Application data with bytes in it, or the node's close_notify, is the spare dying. */
        if (rc != 0)
            return -1;
    }
}

static int spare_read(session *s)
{
    /* One read of the reference's size — node_fill — and whatever whole records it made. The end
     * of the stream is the spare dying, as is a socket that failed. */
    if (node_fill(s, node_want(s)) < 0)
        return -1;
    return spare_records(s);
}

#if LC_HYSTERIA

/* ---- the Hysteria2 plane, continued ------------------------------------------ */

/* A datagram from the node, on its way back to whoever asked for it.
 *
 * Called from inside lc_qconn_step, with the packet already whole — if it arrived in pieces they
 * were put back together before this. The session it belongs to is found by the number the node
 * echoed back, which is the number we chose when the session was opened.
 *
 * Where it came from is not checked against where we sent it, and that is deliberate rather than
 * missed: a session here has exactly one destination, and the node resolved the name for us, so the
 * address in the answer is one this side has never seen and could not compare against. What bounds
 * it is that the session carries one destination at all. */
/* The destination as the node expects to read it, which for IPv6 means brackets.
 *
 * The node parses what we send with Go's net.Dial / ResolveUDPAddr (vendor/hysteria, core/server),
 * and the reference builds the string with dstAddr.String() — netip's formatting, which brackets an
 * IPv6 address (vendor/hysteria/app/internal/tproxy/udp_linux.go:71 and :80 and
 * vendor/hysteria/app/internal/redirect/tcp_linux.go:62). We built it with "%s:%u" over the bare
 * inet_ntop text, so 2001:db8::1 port 443 went out as `2001:db8::1:443`, and Go answers that with
 * "too many colons in address" — every IPv6 destination
 * on the Hysteria2 plane refused, for a reason no log on this side would name. */
static void node_addr(char *out, size_t cap, const char *host, uint16_t port)
{
    if (strchr(host, ':') != NULL)
        snprintf(out, cap, "[%s]:%u", host, (unsigned)port);
    else
        snprintf(out, cap, "%s:%u", host, (unsigned)port);
}

/* Defined below, beside the feed it drives: the connection is handed this when it is opened, and
 * the write loop calls it whenever ngtcp2 runs out. See lc_qrefill_fn in src/quic/conn.h. */
static int hy_refill(void *user);

/* One packet of a Hysteria2 datagram session onto the client's socket, as the reference's
 * forwarding writes it: conn.Write, and then updateConnDeadline — the session's idle clock starts
 * over once the packet has gone (vendor/hysteria/app/internal/tproxy/udp_linux.go:97-110). 0 when it
 * went; 1 when the socket was full and the packet is kept in the session, the socket watched — see
 * reply_wait; -1 when the write failed otherwise, which ends the forwarding and with it the session
 * (the error closes both of its connections). */
static int hy_reply(session *s, int out, const uint8_t *data, size_t len)
{
    for (;;) {
        if (sendto(out, data, len, MSG_NOSIGNAL, (struct sockaddr *)&s->peer, s->peer_len) >= 0) {
            stats.udp_bytes_down += len;
            s->idle_deadline = lc_now_ms() + UDP_IDLE_MS;
            return 0;
        }
        if (errno == EINTR)
            continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return -1;
        if (s->reply_held == NULL || s->reply_held != data) {
            uint8_t *copy = malloc(len > 0u ? len : 1u);
            if (copy == NULL)
                return own_failure(s);
            memcpy(copy, data, len);
            free(s->reply_held);
            s->reply_held = copy;
            s->reply_held_len = len;
        }
        return reply_wait(s, out) != 0 ? -1 : 1;
    }
}

static int hy_datagram(void *user, int session_id, const char *addr, const uint8_t *data,
                       size_t len)
{
    /* The connection the session id belongs to: ids are numbered per connection. */
    const hy_link *k = user;

    /* WHICH ADDRESS ANSWERED IS NOT LOOKED AT, as the reference does not look at it: every datagram
     * of the session goes out of the pair's own socket (see reply_socket_for), which is what the
     * paragraph above has always said. The address used to be split back out of the node's
     * spelling of it and compared, and a reply from anywhere else was dropped. */
    (void)addr;

    for (unsigned i = 0; i < sessions_cap; i++) {
        session *s = sessions[i];
        if (s == NULL || s->closing || !s->is_udp || s->hy_h != session_id || s->hy_gen != k->gen)
            continue;

        int out = reply_socket_for(s, NULL, 0);
        /* `continue`, not `return`: the loop is over every session, and one that cannot be answered
         * must not end the sweep for the rest. Only one matches this session id today, which is
         * exactly why a `return` here would have gone unnoticed. */
        if (out < 0)
            continue;
        /* Out of the socket bound to the address the client was talking to when there is one. The
         * listener would answer from its own address, and to the client that is a different host
         * saying something unasked-for.
         *
         * A socket with no room is waited for, and what the node sends meanwhile waits in the
         * session's channel — see hy_reply and LC_QUDP_CHAN. A write that fails otherwise ends the
         * session; it is closed by the sweep, as this runs inside the connection and may not close
         * one itself (see lc_qudp_fn). */
        int r = hy_reply(s, out, data, len);
        if (r < 0)
            s->idle_deadline = 0;
        return r > 0;
    }
    return 0;
}

/* Opens the one connection every session will ride: QUIC, then the authentication exchange over
 * HTTP/3 on top of it. Both are driven to completion here rather than in the loop, because until
 * they finish there is nothing this process can carry — and the loop exists to stop one connection
 * from blocking others, of which there are none yet. */
/* Said wherever the handshake ends without completing, as it is in lc-hy, lc-hyfetch and lc-hydns.
 * A pin that no longer matches ends the connection from inside qtls.c, which from out here looks
 * exactly like a node that never answered. */
static void pin_hint(void)
{
    if (hy.have_pin)
        note("  (a pin that does not match the node's certificate ends the handshake the"
             " same way — check `option pin` before blaming the path)");
}

/* Open the connection and STOP THERE. The handshake and the authentication are waited for by the
 * loop like everything else — see hy_advance.
 *
 * This function used to do all three, with a ten-second loop for each wait, and those twenty seconds
 * were twenty seconds in which nothing else in this process ran. The reference has no such problem
 * to solve: in hysteria every proxied connection is its own goroutine, so a client waiting on its
 * own handshake waits alone. One thread and one loop cannot copy that by copying code; it copies it
 * by not blocking. */
static int hy_connect(lc_loop *loop)
{
    /* THE RANGE AND THE INTERVAL, HANDED OVER UNCONDITIONALLY — the range is the switch, so there is
     * nothing to decide here.
     *
     * Only a range hops, because that is the only case in which the reference hops at all.
     * vendor/hysteria/app/cmd/client.go:285 chooses the transport by asking whether the server
     * address parsed as a range: `if hyConfig.ServerAddr.Network() == "udphop"` gives
     * NewUDPHopPacketConn, and the else branch is a plain so.ListenUDP() — one socket, opened once,
     * never replaced. A single port is the else branch. The hop interval is read either way (:278)
     * and then goes unused.
     *
     * ⚠️ TWO THINGS STOOD HERE IN TURN, AND BOTH WERE THIS PROJECT'S OWN. First hopping started
     * whenever an interval was configured, range or not, so a single-port node got a new source
     * port every twenty seconds — each one costing every packet already on its way to the port just
     * left, and upstream does no such thing. That was fixed by guarding this call with
     * `if (hy.hop_lo != 0)`, which fixed the behaviour and invented a second question: the caller
     * decided whether to configure hopping, and lc_qconn_hop_on decided again on the same bounds.
     * Now the bounds decide once, inside, and a lo of zero means here what it means everywhere
     * else — no range, so no hopping.
     *
     * Asked for before opening, because the first dial already takes a port from the range. */
    lc_qconn_hop_on(&hy.link->c, hy.hop_min, hy.hop_max, hy.hop_ports.n > 0u ? &hy.hop_ports : NULL);
    /* And for the same reason: this changes the first packet of the handshake, so it cannot be
     * switched on after the connection is open. */
    if (hy.gecko_min != 0)
        lc_qconn_gecko_on(&hy.link->c, hy.gecko_min, hy.gecko_max);
    if (hy.plain)
        lc_qconn_chrome_off(&hy.link->c);

    if (lc_qconn_open(&hy.link->c, hy.node, hy.port, hy.sni, hy.obfs[0] != '\0' ? hy.obfs : NULL,
                      hy.have_pin ? hy.pin : NULL) != 0) {
        /* ⚠️ AND IT COUNTS ON THIS PLANE TOO, or the number would mean one thing on REALITY and
         * nothing at all here. `dial_failed` was added to separate a node that fails FAST from one
         * that hangs, and the separation has to be the same separation on both planes: this is an
         * error coming back from the open, so it belongs in it. The two places that give up on a
         * `pending_deadline` deliberately do NOT count — a deadline that expired is the other kind,
         * and lumping them together would put the summary back where it started. */
        stats.dial_failed++;
        note("cannot reach the node: %s", hy.link->c.err);
        lc_qconn_close(&hy.link->c);
        return -1;
    }

    /* Watched from now, not from the end: the packets of the handshake arrive on this descriptor and
     * the loop is what reads them. */
    if (lc_loop_add(loop, lc_qconn_fd(&hy.link->c), LC_EV_READ, &hy_tag) != 0) {
        note("cannot watch the node's socket");
        lc_qconn_close(&hy.link->c);
        return -1;
    }
    hy.link->fd = lc_qconn_fd(&hy.link->c);
    hy.link->wake_fd = lc_qconn_wake_fd(&hy.link->c);
    if (hy.link->wake_fd < 0 || lc_loop_add(loop, hy.link->wake_fd, LC_EV_READ, &hy_tag) != 0) {
        note("cannot watch the node connection's send queue");
        lc_loop_del(loop, hy.link->fd);
        hy.link->fd = -1;
        hy.link->wake_fd = -1;
        lc_qconn_close(&hy.link->c);
        return -1;
    }
    hy.pending = 1;
    hy.pending_deadline = lc_now_ms() + LC_HY_HANDSHAKE_MS;
    return 0;
}

/* Everything that becomes true once the node has said yes. */
static int hy_open(lc_loop *loop, session *s);

static void hy_ready(lc_loop *loop)
{
    /* Each connection tells its own callbacks which one it is: ids and handles are numbered per
     * connection, and a connection let go of still delivers. */
    lc_qconn_udp_handler(&hy.link->c, hy_datagram, hy.link);
    lc_qconn_refill_handler(&hy.link->c, hy_refill, hy.link);

    /* A new connection is a new generation, and every handle issued before it is now meaningless. */
    hy.link->gen = ++hy.gen;
    hy.link->up = 1;
    hy.link->udp = hy.pending_auth.udp_enabled;
    /* Said on every connection rather than only at startup, and said plainly. A reconnect is where
     * an interception would be introduced, and "authenticated" is the one word that separates
     * carrying traffic to the node from carrying it to whatever answered in its place.
     *
     * Three states, because there are three. This had only two arms and the second of them named a
     * cause — "no pin given" — so a run started WITH a pin that had not been matched said the pin was
     * missing, which sends whoever reads the log to add an option that is already there. Its three
     * sibling tools have had the middle arm from the beginning; only the one that carries the
     * household's traffic did not.
     *
     * That middle arm is not reachable in practice: a pin that does not match ends the handshake
     * inside qtls.c, so hy_connect gives up above this line rather than reaching it. It stays because
     * the verdict must not be able to lie if that ever stops being true — and the wording says so
     * rather than pretending the state is ordinary. */
    /* The port the connection is ACTUALLY on, which with a range is not the one on the command
     * line: the first dial already picks from it. Printing hy.port there named a port nothing was
     * talking to, in the one line anybody reads to check what the tunnel is doing. */
    note("node %s:%u, udp %s%s, %s — %s", hy.node, lc_qconn_port(&hy.link->c),
           hy.pending_auth.udp_enabled ? "yes" : "no",
           hy.rx_rate > 0 ? ", we asked to receive at a stated rate" : "", lc_qconn_suite(&hy.link->c),
           lc_qconn_pinned(&hy.link->c)
               ? "the node holds the pinned certificate"
               : hy.have_pin
                     ? "NOT authenticated: the pin was given and is not matched, which should be "
                       "impossible past the handshake"
                     : "NOT authenticated: no pin given, so any peer that completed the "
                       "handshake would have been accepted");

    /* WHAT THE NODE ANSWERED ABOUT RATE, AND WHY IT DECIDES NOTHING HERE — WHICH IS THE REFERENCE.
     *
     * The reference reads this header and chooses its controller on it, but through the CLIENT'S
     * OWN send rate as well (vendor/hysteria/core/client/client.go:149-166):
     *
     *     actualTx = authResp.Rx
     *     if actualTx == 0 || actualTx > c.config.BandwidthConfig.MaxTx {
     *         actualTx = c.config.BandwidthConfig.MaxTx
     *     }
     *     if actualTx > 0 { UseBrutal(...) } else { UseConfigured(...) }
     *
     * MaxTx is `bandwidth.up` from the client's config, and it is zero unless somebody writes one
     * (vendor/hysteria/app/cmd/client.go:479-484: "users [may] omit bandwidth values and use built-in
     * congestion control"). With MaxTx zero, any rate the node states is larger than it, so actualTx
     * becomes zero and the reference takes UseConfigured — BBR — on every node, whatever the node
     * says. This client has no send rate to configure, so it is that reference, and BBR is its answer
     * too. RxAuto takes the same branch.
     *
     * ⚠️ THIS SAID THE OPPOSITE UNTIL 2026-09-22 — "a number means send at this rate and installs
     * Brutal", "the day somebody sets HYSTERIA_DOWN_MBPS on a node they stop agreeing" — and logged
     * "upstream would pace to it with Brutal" on every connection to such a node. It read the first
     * assignment and not the clamp under it. There is no Brutal to implement: the reference without
     * a configured send rate never installs it. */

    /* Everything that waited for this connection now rides it, oldest first: the requests queued on
     * the reference's mutex find the client in place and go on (reconnect.go:69-80). */
    for (;;) {
        session *w = NULL;
        for (unsigned i = 0; i < sessions_cap; i++) {
            session *o = sessions[i];
            if (o != NULL && !o->closing && o->st == ST_HYWAIT && (w == NULL || o->pool_seq < w->pool_seq))
                w = o;
        }
        if (w == NULL)
            break;
        if (hy_open(loop, w) != 0)
            session_close(loop, w);
    }
}

static void hy_give_up(lc_loop *loop, const char *what);

/* One turn of a connection that is still being built.
 *
 * The two waits that used to be loops inside hy_connect, driven by the same loop that serves
 * everything else: a turn here is a step of the QUIC connection and a look at where it has got to.
 * Nothing below waits for anything — that is the whole point of the file this was moved out of. */
static void hy_advance(lc_loop *loop)
{
    if (lc_qconn_step(&hy.link->c, 0) <= 0) {
        /* An error arriving on the socket, not a deadline expiring: the fast half, as above. */
        stats.dial_failed++;
        hy_give_up(loop, "the node's connection ended while it was being built");
        return;
    }

    if (hy.pending == 1) {
        if (hy.link->c.handshake_done) {
            if (lc_qconn_auth_send(&hy.link->c, hy.password, hy.rx_rate) != 0) {
                hy_give_up(loop, hy.link->c.err);
                return;
            }
            hy.pending = 2;
            return;
        }
        /* ⚠️ IDLE FIRST, AND A BUDGET BEHIND IT — both of quic-go's clocks, which is what this got
         * wrong twice in opposite directions.
         *
         * It once read only a deadline set at dial: ten seconds of wall clock, however alive the
         * node was. Then only the idle clock, measured from the last packet in. quic-go has both
         * (vendor/quic-go/connection.go:887-892): `DefaultHandshakeIdleTimeout = 5 * time.Second`
         * (vendor/quic-go/internal/protocol/params.go:97) from idleTimeoutStartTime, and
         * `handshakeTimeout() = 2 * HandshakeIdleTimeout` (vendor/quic-go/config.go:17-19) from the
         * connection's creation.
         *
         * The idle one is the one that matters on a path that drops large packets. Our ClientHello
         * is 1515 bytes and always spans two Initials; when one is lost the node ACKs the other and
         * waits, ngtcp2 arms a PTO and retransmits — and a clock that was not restarted by that
         * progress killed the connection while it was still working. Measured on the node
         * 2026-09-03: attempts where both Initials arrived completed; where one was lost, the node
         * answered with a bare ACK and the connection was torn down instead of letting the
         * retransmit land.
         *
         * IDLE IS QUIC'S IDLE, restarted by a packet in and by the first ack-eliciting packet out
         * after it — see lc_qconn_idle_ms. Measuring from the last packet in alone gave up to a PTO
         * earlier than the reference whenever our own retransmit was the last thing on the wire.
         * Rubbish from anything that can reach the port does not restart it: only a packet ngtcp2
         * processed does. */
        if (lc_qconn_idle_ms(&hy.link->c) >= LC_HY_HANDSHAKE_IDLE_MS || lc_now_ms() >= hy.pending_deadline) {
            /* The pin is checked inside the handshake — see qtls.c — so a digest that is merely out
             * of date leaves through this line, indistinguishable from a path that dropped the
             * packets. The three probes all say this; the daemon, whose log is the only one anybody
             * reads, said nothing and left the reader chasing the network for a line in a config
             * file. */
            note("the node did not complete a QUIC handshake: %s",
                 hy.link->c.err[0] ? hy.link->c.err
                             : "no reason recorded, which is what a silent path looks like");
            pin_hint();
            stats.gave_up_connecting++;
            /* In silence, as quic-go ends a handshake for either clock — see `silent` in
             * quic/conn.h. */
            hy.link->c.silent = 1;
            hy_give_up(loop, "not connected");
        }
        return;
    }

    /* ⚠️ NO CLOCK ON THE ANSWER, and there were ten seconds here that closed the connection with 0x100
     * and dialled again. The reference's RoundTrip waits on the connection and nothing else
     * (vendor/hysteria/core/client/client.go:133): a node slow to answer is waited for, and a node
     * that never answers is noticed by QUIC's idle timeout, with the keep-alive holding it open for as
     * long as the node acknowledges. */
    int done = lc_qconn_auth_poll(&hy.link->c, &hy.pending_auth);
    if (done < 0) {
        hy_give_up(loop, hy.link->c.err);
        return;
    }
    if (done == 0)
        return;

    hy.pending = 0;
    hy_ready(loop);
}

/* Drops the socket a hop left behind, when there is one. Both places that close the connection have
 * to do this, and doing it in one function is what stops them from drifting apart. */
static void hy_unwatch_prev(lc_loop *loop, hy_link *k)
{
    int prev = lc_qconn_prev_fd(&k->c);
    if (prev >= 0)
        lc_loop_del(loop, prev);
}

/* Gives up on a connection being built, and says which stage it was at.
 *
 * AND THE REQUEST THAT ASKED FOR IT FAILS, and the next one asks again at once. In the reference each
 * request that finds no connection makes one itself, one at a time under the client's mutex: the
 * first to hold it dials, fails, and returns its error to its own caller; the next takes the mutex,
 * finds no client and dials in turn (vendor/hysteria/core/client/reconnect.go:69-78). No wait, no
 * ladder, and no attempt that nobody asked for — so the oldest waiting request is closed here and, if
 * another is waiting, the next attempt is its own.
 *
 * ⚠️ WHAT STOOD IN THIS PLACE WAS A BACKOFF — five hundred milliseconds doubling to thirty seconds,
 * with jitter — and a reconnect the loop made on its own whenever the connection was down, with or
 * without traffic, while every new request was refused. On the wire that is a stream of jittered
 * handshakes to an idle or dead node where the reference makes none until somebody asks, and then one
 * per request. */
static void hy_give_up(lc_loop *loop, const char *what)
{
    note("%s", what);
    if (hy.link->fd >= 0)
        lc_loop_del(loop, hy.link->fd);
    /* And the one a hop left behind, if there was one. lc_qconn_close closes both, and a descriptor
     * closed while still in the loop is a registration for a number the kernel is free to hand to
     * the next socket this program opens. Nothing here has hopped yet — this path gives up on a
     * connection still being built — but the two closes are in one function and so are the two
     * deletions, which is the version of this that stays true when the paths move. */
    hy_unwatch_prev(loop, hy.link);
    hy.link->fd = -1;
    /* Before the close below, which closes the pipe: a descriptor closed while still in the loop is
     * a registration for a number the kernel may hand to the next thing this program opens. */
    if (hy.link->wake_fd >= 0)
        lc_loop_del(loop, hy.link->wake_fd);
    hy.link->wake_fd = -1;
    hy.pending = 0;
    lc_qconn_close(&hy.link->c);

    for (;;) {
        session *w = NULL;
        for (unsigned i = 0; i < sessions_cap; i++) {
            session *o = sessions[i];
            if (o != NULL && !o->closing && o->st == ST_HYWAIT && (w == NULL || o->pool_seq < w->pool_seq))
                w = o;
        }
        if (w == NULL)
            return;
        stats.gave_up_handshake++;
        session_close(loop, w);
        /* The next one in the queue, if any, makes its own attempt. One that cannot even begin fails
         * its request the same way, and the one after it tries. */
        int waiting = 0;
        for (unsigned i = 0; i < sessions_cap; i++) {
            session *o = sessions[i];
            if (o != NULL && !o->closing && o->st == ST_HYWAIT)
                waiting = 1;
        }
        if (!waiting || hy_connect(loop) == 0)
            return;
    }
}


/* Ends a connection and everything riding it. Called when the node has gone: there is nothing to
 * salvage, because every session on it was a stream on the connection that just ended.
 *
 * The one new requests use stays the client, dead, until a request trips over it — see hy.dead. One
 * that had been let go of is simply gone, as the reference's dropped client is once its connection
 * ends. */
static void hy_drop_link(lc_loop *loop, hy_link *k)
{
    if (!k->up)
        return;
    k->up = 0;
    if (k->fd >= 0)
        lc_loop_del(loop, k->fd);
    hy_unwatch_prev(loop, k);
    k->fd = -1;
    /* Before the close below, which closes the pipe: a descriptor closed while still in the loop is
     * a registration for a number the kernel may hand to the next thing this program opens. */
    if (k->wake_fd >= 0)
        lc_loop_del(loop, k->wake_fd);
    k->wake_fd = -1;

    for (unsigned i = 0; i < sessions_cap; i++) {
        session *s = sessions[i];
        if (s != NULL && !s->closing && s->hy_h != 0 && s->hy_gen == k->gen) {
            s->hy_h = 0; /* the connection is going; there is no stream left to close politely */
            s->hy_read = 0;
            session_close(loop, s);
        }
    }
    lc_qconn_close(&k->c);
    if (k == hy.link) {
        /* Gone, but still the client as far as the next request is concerned — see hy.dead. */
        hy.dead = 1;
        return;
    }
    for (unsigned i = 0; i < hy.nleft; i++) {
        if (hy.left[i] == k) {
            hy.left[i] = hy.left[--hy.nleft];
            break;
        }
    }
    free(k);
}

/* Every connection, at the end of the process. */
static void hy_drop(lc_loop *loop)
{
    while (hy.nleft > 0)
        hy_drop_link(loop, hy.left[hy.nleft - 1]);
    hy_drop_link(loop, hy.link);
}

/* LETS GO OF THE CONNECTION NEW REQUESTS USE, and leaves it carrying: reconnectableClientImpl's
 * `rc.client = nil` after a call came back ClosedError (vendor/hysteria/core/client/reconnect.go:
 * 80-88). The streams and datagram sessions already on it go on, on it, until they end or it does;
 * the next request finds no client and dials. See hy_link. */
static void hy_let_go(void)
{
    hy_link *fresh = calloc(1, sizeof *fresh);
    hy_link **grown = realloc(hy.left, (hy.nleft + 1u) * sizeof *hy.left);

    if (fresh == NULL || grown == NULL) {
        /* No memory to hold it apart: the connection stays the client. The session that tripped over
         * it has failed either way, and that is the one failure the reference reports too. */
        free(fresh);
        if (grown != NULL)
            hy.left = grown;
        return;
    }
    hy.left = grown;
    hy.left[hy.nleft++] = hy.link;
    fresh->fd = -1;
    fresh->wake_fd = -1;
    hy.link = fresh;
}

/* One datagram towards the node, with the destination that travels with it.
 *
 * Dropping here is the LAST resort and no longer the first, which is a correction rather than a
 * refinement: this used to say "nothing is queued — a datagram the connection cannot take right now
 * is a datagram dropped, which is what UDP is", and that is a reading of UDP, not of the reference.
 * quic-go blocks its caller when the datagram queue is full rather than refusing the frame, so the
 * burst waits in the client's socket buffer; the gate in the loop does the same by not reading. See
 * LC_QUDP_QUEUE in src/quic/conn.h. What still reaches this line is a datagram already read, which
 * there is nowhere to put back — and for that one, dropping is the only thing left. */
static int hy_send_datagram(session *s, const char *host, uint16_t port, const uint8_t *data,
                            size_t len)
{
    /* An empty datagram goes out only as the pair's FIRST: newPair hands its initial packet to Send
     * as read, `buf[:n]` with no test (vendor/hysteria/app/internal/tproxy/udp_linux.go:34-43, sent at
     * :71), and the pair's own loop sends later ones only `if n > 0` (:116-118). ⚠️ Until 2026-09-27 an
     * empty first packet was dropped here, and no message went to the node for it. */
    int first = !s->hy_first_sent;
    s->hy_first_sent = 1;
    if (len == 0 && !first)
        return 0;

    /* The datagram's own destination, for the same reason as on the other plane: a Hysteria UDP
     * frame states its address too — session, packet id, frag, count, then the address — so one
     * session serves every address a client talks to, and the address is not a property of the
     * session to be read off it. */
    char addr[300];
    node_addr(addr, sizeof addr, host, port);

    /* On the connection the session was opened on, which is not always the one new requests use. */
    hy_link *k = hy_link_of(s);
    int      sent = k != NULL ? lc_qconn_udp_send(&k->c, s->hy_h, addr, data, len) : -1;
    if (sent == 1) {
        /* Over MaxUDPSize with its header: dropped in silence, and the caller goes on as after a send
         * — see lc_qconn_udp_send. Counted, since this side can. */
        stats.udp_dropped++;
        return 0;
    }
    if (sent != 0) {
        stats.udp_dropped++;
        if (!udp_drop_said) {
            udp_drop_said = 1;
            note("dropped a %zu-byte datagram for %s (further ones are counted, not "
                 "logged, until the next summary)",
                 len, addr);
        }
        return -1;
    }
    /* The other plane's uplink, counted where it actually leaves — see udp_pump. */
    stats.udp_bytes_up += (uint64_t)len;
    return 0;
}

/* A request on the Hysteria2 plane: carried now if the node's connection is up, and otherwise made to
 * wait for one — which it asks for, if nobody has.
 *
 * ⚠️ IT USED TO BE REFUSED. With the connection down every new request was closed at once while the
 * loop reconnected on its own schedule. The reference's client does the opposite on both counts: a
 * request that finds no connection makes one, and waits for it (vendor/hysteria/core/client/
 * reconnect.go:69-78), and nothing reconnects while nothing asks. */
static int hy_start(lc_loop *loop, session *s, const char *host, uint16_t port)
{
    snprintf(s->target_host, sizeof s->target_host, "%s", host);
    s->target_port = port;
    s->began_ms = lc_now_ms();

    if (hy.link->up)
        return hy_open(loop, s);

    /* THE FIRST REQUEST AFTER THE CONNECTION DIED FAILS, AND ONLY THE ONE AFTER IT DIALS.
     *
     * clientDo hands the request the client it still holds; TCP() opens a stream on a closed
     * connection, OpenStream fails, and wrapIfConnectionClosed makes that ClosedError
     * (vendor/hysteria/core/client/client.go:193-197, :255-262) — which goes back to the caller, whose
     * connection is closed, and only then is rc.client set to nil (reconnect.go:79-88). UDP() fails the
     * same way on a closed session manager (vendor/hysteria/core/client/udp.go:147-151).
     *
     * ⚠️ UNTIL 2026-09-27 the next request reconnected at once and succeeded: one request sooner than
     * the reference, and one LAN connection fewer refused per connection lost. */
    if (hy.dead) {
        hy.dead = 0;
        return -1;
    }

    s->st = ST_HYWAIT;
    s->pool_seq = ++hy.wait_seq;
    if (hy.pending == 0 && hy_connect(loop) != 0)
        return -1;
    return 0;
}

/* Asks the node to open a stream or a datagram session for a request whose target is already on it,
 * and registers the client side. The node's answer to a stream arrives later, on the shared
 * connection, which is why this leaves a stream short of open. */
static int hy_open(lc_loop *loop, session *s)
{
    const char *host = s->target_host;
    uint16_t    port = s->target_port;

    /* A datagram session is open the moment it exists. There is no request to send and no answer to
     * wait for: the number is ours to choose, the destination travels with every packet, and the
     * node learns of the session from the first one that arrives. */
    if (s->is_udp) {
        if (!hy.link->udp) {
            note("the node does not relay datagrams for us");
            return -1;
        }
        s->hy_h = lc_qconn_udp_open(&hy.link->c);
        s->hy_gen = hy.link->gen;

        if (s->hy_h < 0) {
            s->hy_h = 0;
            s->hy_read = 0;
            note("cannot open a session for %s:%u: %s", host, port, hy.link->c.err);
            return -1;
        }
        s->st = ST_OPEN;
        /* The question that started this session goes now. If it is dropped the session still
         * stands: what asks over UDP asks again, and refusing the session for one lost datagram
         * would turn a retry into a failure. */
        (void)pend_flush(s, hy_send_datagram);
        return 0;
    }

    char addr[300];
    node_addr(addr, sizeof addr, host, port);

    s->hy_read = 0;
    s->hy_h = lc_qconn_tcp_open(&hy.link->c, addr);
    s->hy_gen = hy.link->gen;
    if (s->hy_h < 0) {
        s->hy_h = 0;
        s->hy_read = 0;
        note("cannot open a stream for %s: %s", addr, hy.link->c.err);
        return -1;
    }
    /* The stream exists; what remains is the node saying whether it reached the target — for as long
     * as it takes, as the reference's ReadTCPResponse waits (vendor/hysteria/core/client/client.go:216). */
    s->st = ST_HANDSHAKE;
    s->deadline = 0;

    if (lc_loop_add(loop, s->lan_fd, 0, &s->lan_tag) != 0)
        return -1;
    s->lan_on_loop = 1;

    /* The client is NOT read yet: hy_pump hands it to the reader when the node's answer is in —
     * see hy_reading. */
    return session_rearm(loop, s);
}

/* THE CLIENT IS READ FROM ONLY ONCE THE NODE HAS SAID YES, because that is when the reference starts
 * its copies: HyClient.TCP returns after ReadTCPResponse, and only then do the two io.Copy
 * goroutines begin (vendor/hysteria/app/internal/tproxy/tcp_linux.go:51-68). Until then what the
 * client sends stays in the kernel, and so does its end.
 *
 * ⚠️ UNTIL 2026-09-27 the reader took it from the moment the stream was opened. Nothing went to the
 * node early — hy_feed_up hands bytes on only to an open stream — but a client that closed while
 * the node was still dialling ended the stream then, before the answer, where the reference waits
 * for the answer and ends it after; and a refusal closed a socket whose bytes had been read, a FIN
 * to the client where the reference's close of an unread socket is a reset.
 *
 * The same descriptor goes to the reader for reading only. Two epolls watch it and they want
 * different things: this loop wants to know when the client can be WRITTEN to, the reader wants to
 * know when it can be READ from, and neither is told about the other's. What the reader fills is
 * this session's own uplink queue — no second buffer — under the stage's lock. */
static int hy_reading(session *s)
{
    if (lc_reader_add(&s->stage, s->lan_fd, s->to_up.buf, s->to_up.cap, &s->to_up.len,
                      &s->to_up.off) != 0) {
        note("cannot hand %s:%u to the reader", s->target_host, s->target_port);
        return -1;
    }
    return 0;
}

/* Moves whatever can move for one session, in both directions. Returns -1 when the session is over.
 *
 * Called for every session on the plane after every turn of the connection, because bytes for any
 * of them arrive on the one socket and there is no event that says which. A walk of every session
 * rather than a list of those with something waiting: what bounds it is the node's MAX_STREAMS, 1024
 * on a stock server. ⚠️ "WITH SIXTEEN STREAMS AT MOST" stood here, from a table long since gone —
 * the last one held 256 and was lifted on 2026-09-27 (LC_QTCP_MAX). */
/* What the client sent, handed to the stream, as far as the stream will take it this moment.
 *
 * Its own function because the read that fills this queue wants it too. The reference's uplink is
 * `io.Copy(rc, conn)` in a goroutine of its own (vendor/hysteria/app/internal/forwarding/tcp.go:54,
 * and the same pair in redirect/tcp_linux.go:72), which is a read and a write alternating with
 * nothing in between; here the read lives in the event loop and the write lived only in hy_pump, so
 * one turn of the loop could move one bufferful and no more. Alternating them needs the write
 * reachable from the read, which is all this move does — hy_pump's behaviour is unchanged. */
/* Bytes from the client onto its stream, and NOTHING else — no verdict about the session's end,
 * because this is also called from inside the connection's write loop (hy_refill below), where
 * ending a session is not allowed. Returns how many bytes it handed over. */
static size_t hy_feed_up(session *s)
{
    /* THE GENERATION FIRST, AND IT BELONGS HERE RATHER THAN AT THE CALLER. hy_ready says it in as
     * many words — "a new connection is a new generation, and every handle issued before it is now
     * meaningless" — and hy_turn acts on it by closing such a session instead of pumping it. But
     * hy_turn runs at the END of a turn, and the read that now calls this runs at the start of the
     * next one, so between a reconnect and that reaping there is a whole turn in which a session of
     * the previous generation can have a readable socket.
     *
     * A handle is sixteen bits of slot and fifteen of generation, and a fresh connection starts its
     * slots again from zero — so a handle left over from the last one does not merely fail to
     * resolve, it can resolve to SOMEBODY ELSE'S stream in the new connection. That would put one
     * client's bytes into another client's connection, which is the worst failure this file can
     * have and would look like a remote fault.
     *
     * hy_pump's caller checks the same thing, so this costs it one comparison and protects the
     * caller that cannot. The connection is the one the session's generation names, which since
     * connections can be let go of and go on carrying is not always the one new requests use. */
    hy_link *k = hy_link_of(s);
    if (k == NULL) {
        stats.up_stale_gen++;
        return 0;
    }

    /* Not before the node has answered: until then the stage is not the reader's, and its lock not
     * yet made — see hy_reading. */
    if (s->st != ST_OPEN)
        return 0;

    /* THE LOCK, AND EXACTLY WHAT IT COVERS: `to_up.len`, `to_up.off` and the reader's two verdicts.
     * The reader appends at `len`; this hands out from `off` and resets both when the queue empties.
     * Nothing else about the session is shared, and nothing inside this lock may block — which is
     * why what it holds is a memcpy into the stream's buffer and not the stream's own work. */
    pthread_mutex_lock(&s->stage.lock);

    size_t pending = q_pending(&s->to_up);
    size_t sent = 0;

    if (pending > 0 && s->st == ST_OPEN && s->hy_h != 0) {
        sent = lc_qconn_tcp_send(&k->c, s->hy_h, s->to_up.buf + s->to_up.off, pending);
        s->to_up.off += sent;
        if (s->to_up.off == s->to_up.len)
            s->to_up.off = s->to_up.len = 0;
    }

    pthread_mutex_unlock(&s->stage.lock);

    if (sent > 0) {
        stats.bytes_out += (uint64_t)sent;
        stats.rec_out++;
        /* Room again, said outside the lock because lc_reader_rearm takes it itself. */
        lc_reader_rearm(&s->stage);
    }
    return sent;
}

/* Every session topped up, for the connection's write loop to call when ngtcp2 has run out.
 *
 * This is the whole of what lc_qrefill_fn allows: bytes staged on streams, no verdict about any
 * session's end and nothing said to the event loop. A session whose client has finished is reaped
 * by hy_pump on the ordinary path, one turn later at worst — which is where it was reaped before
 * this existed, so nothing about that changed.
 *
 * Returns nonzero if anything was handed over, which is what tells the write loop to go round
 * again rather than give up. */
static int hy_refill(void *user)
{
    const hy_link *k = user;
    size_t         fed = 0;

    if (!k->up)
        return 0;

    for (unsigned i = 0; i < sessions_cap; i++) {
        session *s = sessions[i];

        if (s == NULL || s->closing || s->is_udp || s->hy_h == 0 || s->hy_gen != k->gen)
            continue;
        fed += hy_feed_up(s);
    }
    return fed > 0;
}

/* The same bytes, plus the verdict that only the ordinary path may act on. */
static int hy_send_up(session *s)
{
    int    ended, failed;
    size_t left;

    /* The client's end, like its bytes, is taken only once the node has answered: see hy_reading. */
    if (s->st != ST_OPEN)
        return 0;

    (void)hy_feed_up(s);

    /* The lock again rather than one pass that both feeds and judges: the write loop calls the
     * feed and must not be handed a verdict it is not allowed to act on. An uncontended mutex is
     * the cheaper half of that trade by a wide margin. */
    pthread_mutex_lock(&s->stage.lock);
    ended = s->stage.eof || s->stage.err != 0;
    failed = s->stage.err;
    left = q_pending(&s->to_up);
    pthread_mutex_unlock(&s->stage.lock);

    /* THE CLIENT'S END, WHICH ONLY THE READER SEES NOW — and not one byte before everything it sent
     * has been passed on. The reference ends the pair as soon as either copy ends
     * (vendor/hysteria/app/internal/redirect/tcp_linux.go:69-79), and it ends them AFTER the copy
     * has drained what it read; ending here while anything is still standing would throw away the
     * tail of an upload that the client had already handed over. */
    if (ended && left == 0) {
        if (failed)
            note("%s:%u ended while sending: %s", s->target_host, s->target_port, strerror(failed));
        return -1;
    }

    return 0;
}

/* The copy from the node's stream to the client: io.Copy's loop, see the note on it below. -1 when
 * the client's socket fails; nothing here closes anything.
 *
 * It runs once the connection has read what was waiting, as every session's pump does. The
 * reference's copy runs in a goroutine of its own, beside the connection's loop and on another core
 * when there is one, so on a path with almost no delay its window updates come more evenly than
 * these (DIVERGES: G5). Running it from inside the receive loop after every batch of datagrams made
 * them as even and cost the MT7621 a seventh of its CPU per byte; with 20 to 60 ms of delay the
 * two are level without it (tools/vendorcap/qstand, 2026-09-27). */
static int hy_copy_down(hy_link *k, session *s)
{
    /* ONE READ AT A TIME, AS io.Copy READS. The reference copies a stream to the client with io.Copy
     * into the TCPConn, which takes it through genericReadFrom to copyBuffer's 32 KiB buffer
     * (GOROOT/src/net/tcpsock_posix.go:47-54, GOROOT/src/net/net.go:770-773,
     * GOROOT/src/io/io.go:407-418): Read up to 32 KiB, Write all of it, and only then Read again —
     * and a Read is what the node is credited with. This took whatever fitted the queue, crediting
     * in steps of its room, 23 KB, while earlier bytes were still waiting to go; the credit came in
     * other steps than the reference's, and so did the window updates they made due. Now a Read is
     * made only when the last one has all gone out, and its bytes then go into the queue as it has
     * room. */
    for (;;) {
        size_t         have = 0;
        const uint8_t *data = lc_qconn_tcp_peek(&k->c, s->hy_h, &have);
        int            wrote = 0, full = 0;
        if (s->hy_read == 0 && q_pending(&s->to_lan) == 0 && have > 0) {
            s->hy_read = have < 32768u ? have : 32768u;
            lc_qconn_tcp_read(&k->c, s->hy_h, s->hy_read);

            /* AND io.Copy'S WRITE, the whole Read in one call, from where the bytes already lie.
             * Through the queue, which holds 23 KB, 32 KiB took two writes — forty per cent more
             * calls into the kernel than before the Read was 32 KiB, measured on the MT7621 as a
             * tenth more CPU per byte. Only what the socket does not take is copied to the queue. */
            data = lc_qconn_tcp_peek(&k->c, s->hy_h, &have);
            ssize_t n;
            do
                n = write(s->lan_fd, data, s->hy_read);
            while (n < 0 && errno == EINTR);
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                return -1;
            full = n < (ssize_t)s->hy_read;
            if (n > 0) {
                lc_qconn_tcp_take(&k->c, s->hy_h, (size_t)n);
                s->hy_read -= (size_t)n;
                s->got = 1;
                stats.bytes_in += (uint64_t)n;
                stats.rec_in++;
                wrote = 1;
                data = lc_qconn_tcp_peek(&k->c, s->hy_h, &have);
            }
        }
        size_t room = q_room(&s->to_lan);
        size_t take = s->hy_read < room ? s->hy_read : room;
        if (take > 0) {
            if (q_push(&s->to_lan, data, take) != 0)
                return -1;
            lc_qconn_tcp_take(&k->c, s->hy_h, take);
            s->hy_read -= take;

            /* THE ONLY PROOF THAT THIS CONNECTION WORKS: a byte from the node, for somebody.
             *
             * "The stream opened" used to stand here and it is not the same thing — it was measured
             * not being the same thing. On a stalled tunnel the log filled with `opened …` several
             * times a minute while a browser downloaded nothing at all: the node was answering the
             * request to open a stream and delivering none of what came back. Anything that treats
             * opening as health calls that connection fine, which is exactly what happened.
             *
             * `s->got` is per-session and says this particular one has been answered. Nothing on
             * the connection reads it any more — the rule that did is gone — but the session's own
             * end-of-stream handling below still distinguishes "answered nothing" from "answered
             * and finished". */
            s->got = 1;

            /* Counted here because there is nowhere else on this plane where it could be. The
             * summary's byte counters are all filled on the REALITY path — deliver_record fills
             * bytes_in, tls_write fills bytes_out — and a Hysteria2 tunnel touches neither, so
             * every one of them printed a zero while the connection carried a household. Reusing
             * the same two counters rather than adding a pair keeps `datagram share` meaningful:
             * its denominator is stream bytes plus datagram bytes, and with stream bytes stuck at
             * zero that share was 100% by construction, whatever the traffic actually was. */
            stats.bytes_in += (uint64_t)take;
            stats.rec_in++;
        }
        /* A socket that has just taken less than it was given is full: a second write now would only
         * say so. */
        size_t queued = q_pending(&s->to_lan);
        if (!full && queued > 0 && !s->is_udp) {
            if (q_flush(&s->to_lan, s->lan_fd) != 0)
                return -1;
            /* A previous Write finishing is progress too: io.Copy then takes its next Read.
             * Without this, an empty LAN queue can strand an unread tail after the peer's FIN. */
            if (q_pending(&s->to_lan) < queued)
                wrote = 1;
        }
        /* Round again only if this round moved something AND the client took all of it. Anything
         * left in the queue means the socket said no more, and then the next round would take from
         * the stream into a queue with no room — a wasted peek.
         *
         * NOT A WORD OF THIS IS ABOUT DATAGRAMS, and the first version of this comment said it was —
         * that a datagram session takes once and breaks on `q_pending`. It does not reach here at
         * all: hy_pump returns at its top for `is_udp`, and what the node sends back on a datagram
         * session is handed out by hy_datagram from inside the connection, straight to the client's
         * address, with no queue in between. The `!s->is_udp` in the flush above is dead for the
         * same reason and has been since that early return was written; it is left standing only
         * because removing a guard is a change to behaviour nobody has measured, but it must not be
         * read as evidence that datagrams pass this way. */
        if ((take == 0 && !wrote) || q_pending(&s->to_lan) > 0)
            break;
    }
    return 0;
}

static int hy_pump(lc_loop *l, session *s)
{
    /* Nothing to pump for a datagram session: what the client sends goes out the moment it arrives,
     * and what comes back is delivered by hy_datagram from inside the connection. All that is left
     * is the idle sweep, which is not this function's business. */
    if (s->is_udp)
        return 0;

    /* Its own connection, which a connection let go of still is. */
    hy_link *k = hy_link_of(s);
    if (k == NULL)
        return -1;

    const char   *why = NULL;
    lc_qtcp_state st = lc_qconn_tcp_state(&k->c, s->hy_h, &why);

    if (st == LC_QTCP_REFUSED) {
        /* THIS SESSION FAILS AND THE CONNECTION IS NOT TOUCHED, which is upstream's reading of the
         * same event: a refusal is `ok == false` out of ReadTCPResponse and becomes
         * coreErrs.DialError (vendor/hysteria/core/client/client.go:221-224) — an ordinary failed
         * dial, returned to whoever asked, with the client left exactly as it was. The wrapping
         * that discards a client is wrapIfConnectionClosed, and it is only ever applied to errors
         * from OpenStream, WriteTCPRequest and ReadTCPResponse themselves (:196, :202, :219), that
         * is, to QUIC failing rather than to the node saying no.
         *
         * Counting three of them to different destinations and replacing the connection was this
         * tree's rule, at this tree's numbers, and it is gone. Only the count is kept, and only to
         * be printed. */
        stats.stalled++;
        note("the node refused %s:%u: %s", s->target_host, s->target_port,
             why != NULL ? why : "no reason given");
        return -1;
    }
    if (st == LC_QTCP_LOST) {
        /* NAMED AS OURS. The node sent bytes it was entitled to send and this machine had no memory
         * to hold them, so the session ends — and the line says memory, not the node. Reporting a
         * local limit as a far-end failure is what sends the next person to look at it to the wrong
         * end of the wire, and it is the same mistake the descriptor-table case in start_tunnel used
         * to make.
         *
         * The connection is untouched: every other session on this tunnel is still good, and a
         * device short of memory is helped least by losing its one working connection.
         *
         * And WHICH limit, because there are two and they call for different answers: realloc itself,
         * or a buffer already at its ceiling. */
        stats.stalled++;
        note("dropped %s:%u: no room to hold what the node sent: %s (the tunnel is fine)",
             s->target_host, s->target_port, why != NULL ? why : "no reason recorded");
        return -1;
    }
    if (st == LC_QTCP_CLOSED) {
        /* THE REQUEST FAILS AND THE CLIENT LETS GO OF THIS CONNECTION — ClosedError, see
         * LC_QTCP_CLOSED — but only if it still is the client: `if rc.client == client`
         * (vendor/hysteria/core/client/reconnect.go:80-88), a connection already let go of is not
         * let go of twice. Nothing else on it is touched; its other sessions go on. */
        note("%s:%u: %s — the next request makes a new connection", s->target_host,
             s->target_port, why != NULL ? why : "the stream ended before the node's answer");
        if (k == hy.link)
            hy_let_go();
        return -1;
    }
    if (st == LC_QTCP_GONE)
        return -1;
    if (st == LC_QTCP_ESTABLISHED && s->st != ST_OPEN) {
        if (hy_reading(s) != 0)
            return -1;
        s->st = ST_OPEN;
        note_open_wait(s);
        note_opened(s);
    }

    /* Node to client. Taken only as far as there is room to put it, and taking is what re-opens the
     * node's window — so a client that cannot keep up slows the node down rather than this. */
    /* AND IT GOES ROUND UNTIL THE STREAM IS EMPTY OR THE CLIENT IS FULL, because a take is not only
     * a delivery — it is the credit the node is waiting for, and ngtcp2 does not spend it until it
     * is worth a packet.
     *
     * This ran ONCE per turn. One take, bounded by the room in the queue to the client, which is
     * LAN_QUEUE_SIZE and so about 23 KB — and then the turn ended and the loop went back to
     * epoll_wait holding a receive buffer with the rest still in it. Nothing in the loop knows about
     * that buffer: the node's socket is drained to EAGAIN, the client's socket is writable with
     * nothing queued, so no descriptor's readiness can bring us back. What brought us back was the
     * node sending more, and the node could send more only because that one take had returned 23 KB
     * of window.
     *
     * WHY 23 KB AT A TIME IS NOT MERELY SLOWER BUT STALLS, and this is the part that has to be read
     * out of ngtcp2 rather than guessed: a window extension is not put on the wire when it happens.
     * conn_should_send_max_stream_data is `strm->rx.window < 4 * inc`
     * (vendor/ngtcp2/lib/ngtcp2_conn.c:3251-3257), so MAX_STREAM_DATA waits until the untold
     * extension passes a QUARTER of the window; conn_should_send_max_data is the same shape for the
     * connection. With LC_QTCP_STREAM_WINDOW at the 512 KB it held that day, the quarter was
     * 128 KB, which at 23 KB a turn is SIX turns before the node hears one byte of credit — six
     * times whatever wakes this loop.
     *
     * The window is the reference's eight megabytes again since 2026-09-07, so the same arithmetic
     * now gives a quarter of 2 MB and about ninety turns. The defect this loop removed would be an
     * order of magnitude worse today, which is why the loop is load-bearing rather than a tidy-up:
     * it is the thing that makes advertising the reference's number safe at all.
     *
     * Measured from the node with tcpdump, both clients in one capture, told apart by source port.
     * lc-hyfetch: 9 379 packets down, 12 975 628 bytes, in 4.0 s, evenly. This tunnel: 1 550 packets
     * down, 2 101 168 bytes, over 53.3 s — 958 313 bytes in the fourth second at full speed, which
     * is what the window buys before it has to be earned back, and after that bursts of almost
     * exactly 142 000 bytes about every five seconds with the line silent between them. 142 000 is
     * the quarter above, and the silence is a sender that has filled its window waiting for credit
     * this end was holding. Not packets we lost: /proc/net/udp for that socket read rx_queue 0 and
     * drops 0 throughout.
     *
     * The reference has no such pause because it never returns to a scheduler holding data: a
     * Hysteria2 stream is copied by io.Copy in a goroutine of its own, and io.Copy loops on Read
     * until Read has nothing, then blocks in Read rather than in a poller that cannot see it. This
     * loop is that loop. It ends on the same two conditions io.Copy ends on — nothing left to read,
     * or the writer refusing — and it is bounded, not merely terminating: no round can add to the
     * buffer, because bytes enter it only through recv_stream_data_cb and that runs inside
     * lc_qconn_step, which is not called from here; and a round continues only when the queue
     * emptied completely, which restores the full 22 785 bytes of room. So at most a windowful
     * divided by that, about two dozen rounds, and the first short write leaves.
     *
     * AND THE NUMBER, taken the same night on the router against the same node once the path let
     * new flows through again: 40 kB/s before, and after it 860 kB/s, 1.8 MB/s and 2.0 MB/s on three
     * runs — twenty to fifty times, which is lc-hyfetch's own 3.1 MB/s on that box. The first pair
     * of measurements said no change and was wrong for a reason worth keeping: two driver.sh targets
     * running at once raced on build/stamp/gen/flags.stamp, make stopped rebuilding, and every
     * "after" run was the same old binary. It was caught by adding a print to the source and
     * watching the sha256 of the stripped binary not move. When an edit must change the binary,
     * check that it did.
     *
     * WHAT THIS CHANGES ABOUT MEMORY, and the first answer here was wrong in a way worth leaving
     * written down. While the node was held to 23 KB of credit at a time the receive buffer never
     * had to hold much; now that a full window can arrive between two turns, it must be able to
     * reach LC_QTCP_STREAM_WINDOW. The first three runs after the fix all ended in `dropped … no
     * memory to hold what the node sent` — the memory reserve of the time (gone since 29.09, L1)
     * refusing a growth, lc_qrx_put marking over — with MemAvailable at 12 872 KB against a 10 % reserve of 11 870, about a megabyte of
     * slack, and that read like the eight-megabyte failure src/quic/params.h records, returning not
     * because the window is large but because it is finally used.
     *
     * It was not. /tmp on this router is tmpfs, so it is RAM, and it held 12 629 KB of leftover
     * binaries from a night of measuring — mine. Deleting them took MemAvailable to 31 832 KB, and
     * the same transfer then completed twice: all 12 617 813 bytes, once in 90 s and once in 6 s,
     * the second being 2.1 MB/s against lc-hyfetch's 3.2 on that box, with no drop either time. So
     * the machine was not short of memory; the measurement was standing in its own way.
     *
     * What survives is the shape, not the verdict: a window is a promise, and a promise the buffer
     * cannot reach ends a stream rather than slowing it. quic-go does not advertise a fixed window
     * at all — it starts small and auto-tunes upward, so memory follows the transfers that earn it —
     * and that is the shape to take if this is ever seen on a box that is genuinely short.
     *
     * It has still not been seen on one, and that has now been asked of the smallest box we ship
     * to rather than left open: the 118 MB Xiaomi 4A carried the full eight megabytes through five
     * saturating downloads on 2026-09-07 with zero `no memory to hold what the node sent` and zero
     * stream resets, resident in 2 412 KB. What had made the reference's window look unaffordable
     * was the memmove in lc_qrx_take, and it is gone — see the note on `off` in quic/rxbuf.h. */
    if (hy_copy_down(k, s) != 0)
        return -1;

    /* Client to node, as far as the stream will take it this moment — and this is also where the
     * client's own end arrives now, because the descriptor it would have arrived on belongs to the
     * reader thread. */
    if (hy_send_up(s) != 0)
        return -1;

    /* FIN says no more bytes will arrive, not that the buffered bytes have been copied. Before
     * queued-Write progress was counted above, flushing the LAN queue could leave hy_copy_down
     * with unread QUIC data. Closing on FIN and an empty LAN queue alone lost that tail. Keep the
     * unread-buffer guard explicit: quic-go's receiveStream.readImpl copies the final frame before
     * EOF (vendor/quic-go/receive_stream.go:241-251); io.Copy writes those bytes before it ends.
     *
     * The node has finished and everything it sent has been passed on. Both directions end here
     * rather than one: Hysteria2 has no half-close — see lc_qconn_tcp_close — so a stream that has
     * ended has ended entirely, and there is nothing left to wait for. */
    size_t unread = 0;
    (void)lc_qconn_tcp_peek(&k->c, s->hy_h, &unread);
    if (s->st == ST_OPEN && lc_qconn_tcp_eof(&k->c, s->hy_h) &&
        unread == 0 && q_pending(&s->to_lan) == 0)
        return -1;

    return session_rearm(l, s);
}

/* One turn of one carrying connection, then every session on it. */
static void hy_link_turn(lc_loop *loop, hy_link *k)
{

    /* A port hop, when one is due. Done here rather than inside the connection because the loop owns
     * the descriptor: hopping replaces the socket, so the old one has to leave the loop and the new
     * one join it, and only this side knows about the loop at all.
     *
     * Nothing else is disturbed. QUIC is not told, no session is closed, no stream is interrupted —
     * from the protocol's side the connection did not move. See lc_qconn_hop. */
    if (lc_qconn_hop_due(&k->c)) {
        /* THE SOCKET BEFORE LAST LEAVES; THE LAST ONE STAYS. Which is not what stood here — this
         * deleted the socket in use and added it back, so the one the previous hop left behind was
         * never in the loop at all. The connection kept that socket open on purpose and polled it
         * inside lc_qconn_step, but nothing ever WOKE the loop for it, so packets the node was
         * still sending to the old port waited for whatever stirred us next. Upstream reads it with
         * a goroutine of its own and does not wait — see lc_qconn_prev_fd.
         *
         * The one that goes is the generation before last, because lc_qconn_hop is about to close
         * it, and a descriptor must leave the loop before it is closed rather than after. */
        int stale = lc_qconn_prev_fd(&k->c);
        if (stale >= 0)
            lc_loop_del(loop, stale);
        /* The socket in use becomes the previous one and stays watched for reading only — which is
         * all it was ever watched for once the send queue took over the waiting. A hop is taken only
         * with that queue empty (lc_qconn_hop_due), so nothing is addressed to it any more. */

        if (lc_qconn_hop(&k->c) == 0) {
            /* k->fd is still registered and is now the PREVIOUS generation, which is exactly where
             * it should be: kept and watched. Only the new socket has to join. */
            k->fd = lc_qconn_fd(&k->c);
            /* SAID OUT LOUD, and it was not for as long as hopping has existed.
             *
             * This moves the connection every thirty seconds by default, when the node is a port
             * range, and left no trace of having done it, while the failure it is a candidate for
             * — the node going quiet with work
             * waiting — is logged in detail. So the one question worth asking about hopping, whether
             * a silence follows a hop, could not be answered from a router's log even in hindsight;
             * it needed a person watching two things at once. One line makes the correlation
             * readable by anybody who greps a night of syslog. */
            stats.hops++;
            note("moved to source port %u (hop %llu)", (unsigned)lc_qconn_source_port(&k->c),
                 (unsigned long long)stats.hops);

            /* LC_EV_READ, the same as at connect — and it was 0 here for two hours, on a router.
             *
             * An empty mask leaves the descriptor in epoll and wakes for nothing but ERR and HUP,
             * so from the first hop onwards the node's packets were read only when something else
             * woke the loop or its timer expired, up to a second later. Worse for the diagnosis
             * than for the throughput: "how long since the node last spoke" is measured from the
             * last packet WE READ, so the very line written to tell "the node went quiet" from "we
             * were too busy" would have started reporting silence that this bug created. */
            if (lc_loop_add(loop, k->fd, LC_EV_READ, &hy_tag) != 0) {
                note("cannot watch the node's socket after a port hop");
                hy_drop_link(loop, k);
                return;
            }
        } else if (stale >= 0) {
            /* AND A HOP THAT DID NOT HAPPEN PUTS THE REGISTRATION BACK.
             *
             * The line that stood here said a failed hop 'leaves everything as it was, the
             * registration included'. It did not: the delete above is unconditional, and
             * lc_qconn_hop returns without touching prev_fd when the redial fails — so the
             * generation-before-last was left OPEN and UNWATCHED. That socket is kept for one
             * reason, to receive what the node is still addressing to the port we just left, and an
             * unwatched one only gets drained when something else wakes the loop or its timer runs
             * out, up to a second later.
             *
             * Which is the same defect, on the same path, that the paragraph above this one records
             * having found and fixed for the CURRENT generation — where the cost named was not
             * throughput but diagnosis: silence is measured from the last packet WE READ, so an
             * unwatched descriptor manufactures the quiet that the log then reports as the node's.
             *
             * Re-added rather than left, because the descriptor is still ours and still open. */
            if (lc_loop_add(loop, stale, LC_EV_READ, &hy_tag) != 0) {
                note("cannot watch the socket a failed hop left behind");
                hy_drop_link(loop, k);
                return;
            }
        }
    }

    /* AND THIS IS THE ONLY THING THAT ENDS THE NODE'S CONNECTION.
     *
     * QUIC declaring it over — an idle timeout at thirty seconds, a CONNECTION_CLOSE, a transport
     * error — and nothing else. That is upstream's rule exactly: reconnectableClientImpl.clientDo
     * nils its client when a call comes back as coreErrs.ClosedError
     * (vendor/hysteria/core/client/reconnect.go:80-88), and ClosedError is produced in one place,
     * wrapIfConnectionClosed, from errors raised by OpenStream, WriteTCPRequest and ReadTCPResponse
     * — that is, by QUIC failing (vendor/hysteria/core/client/client.go:251-262). A node that
     * refuses a destination gives a DialError and the connection lives on.
     *
     * A rule of our own stood after this line for a long time and is gone. Every version of it read
     * evidence upstream does not act on — first silence at six seconds, then twenty, then eight
     * with a packet outstanding, last three destinations refused inside thirty seconds — and every
     * number in every version was invented here. What they were reacting to was self-inflicted: the
     * port hop replaced the socket every twenty seconds on a single-port node, where the reference
     * does not hop at all, and closed the old socket at once so that everything already sent to it
     * was lost. That is fixed above, in lc_qconn_hop.
     *
     * What the rule bought was noticing a dead path sooner than thirty seconds. What it cost was
     * measured: 119 replacements in two hours, each one aborting every stream in flight and putting
     * another identical handshake on the wire to one address — which is the most recognisable thing
     * a client on a home network can do. */
    if (lc_qconn_step(&k->c, 0) <= 0) {
        /* Both numbers on the line that reports the end, because this is the last moment either one
         * exists and neither is recoverable from the log afterwards. A silence of seconds says the
         * node stopped answering; datagrams that arrived and would not unscramble say something on
         * the path is sending us packets that are not the node's. A party sitting in the middle
         * would much prefer those two cases to look alike, which is the whole reason they are
         * counted strictly enough to be told apart. */
        note("the node's connection ended: %s"
             " (silent for %llu ms, %llu datagrams arrived that were not its)",
             k->c.err[0] != '\0' ? k->c.err : "closed",
             (unsigned long long)lc_qconn_silent_ms(&k->c),
             (unsigned long long)k->c.rx_foreign);
        hy_drop_link(loop, k);
        return;
    }

    int moved = 0;
    for (unsigned i = 0; i < sessions_cap; i++) {
        session *s = sessions[i];
        /* This connection's sessions only. One of another connection is that connection's to pump,
         * and one whose connection has ended is ended by hy_turn. */
        if (s == NULL || s->closing || s->hy_h == 0 || s->hy_gen != k->gen)
            continue;
        moved = 1;
        if (hy_pump(loop, s) != 0)
            session_close(loop, s);
    }

    /* And once more, because the turn above is what produced the things worth sending: bytes from
     * clients, and the window credit that taking bytes off a stream releases. Left to the next
     * turn, both would wait for whatever wakes this loop next — ngtcp2's own timer at best, a whole
     * second at worst — which on a busy stream is a stall per round for no reason at all.
     *
     * ⚠️ AND WHAT THAT STEP READS IS THE SAME CASE AGAIN, one turn later. Datagrams it takes put
     * stream bytes into receive buffers and acknowledgements free room in send buffers, and no
     * descriptor on this loop says so: the sessions are pumped only in the NEXT turn, and the next
     * turn comes when the loop wakes. With nothing else due that is its one-second cap, and the node,
     * waiting for window credit that only a pump releases, waits with it. Measured on the stand as
     * exactly one extra second on one 32 MB transfer in eight, which went away with the cap at
     * 50 ms — and seen only once writes became rarer, since each write used to be followed by a
     * wake of its own. So a step that read anything asks for the next turn at once. */
    k->again = 0;
    if (moved && k->up) {
        uint64_t before = k->c.rx_datagrams;
        (void)lc_qconn_step(&k->c, 0);
        k->again = k->c.rx_datagrams != before;
    }
}

/* One turn of every connection: the one being built or carrying new requests, and the ones let go
 * of that still carry — each of which the reference's client would still be reading and writing,
 * in goroutines of its own. */
static void hy_turn(lc_loop *loop)
{
    /* A connection still being built gets its turn here too, and gets only this: hy_advance steps
     * it and looks at where it has got to. */
    if (hy.pending != 0)
        hy_advance(loop);
    else if (hy.link->up)
        hy_link_turn(loop, hy.link);

    /* Downwards, because a connection that ends in its turn leaves the list and the last one takes
     * its place. */
    for (unsigned i = hy.nleft; i-- > 0;)
        hy_link_turn(loop, hy.left[i]);

    /* Left over from a connection that has ended. Its handle addresses a stream table that no
     * longer exists, so it is ended rather than pumped — and ended without speaking to any
     * connection, which session_close knows not to do. */
    for (unsigned i = 0; i < sessions_cap; i++) {
        session *s = sessions[i];
        if (s != NULL && !s->closing && s->hy_h != 0 && hy_link_of(s) == NULL)
            session_close(loop, s);
    }
}

#else

/* The same names again, doing nothing. A build without the plane still has a loop that asks it for
 * its timer and offers it its turn; what it must not have is a different loop. */
static void hy_turn(lc_loop *loop) { (void)loop; }
static void hy_drop(lc_loop *loop) { (void)loop; }

static int hy_start(lc_loop *loop, session *s, const char *host, uint16_t port)
{
    (void)loop; (void)s; (void)host; (void)port;
    return -1;
}

static int hy_send_datagram(session *s, const char *host, uint16_t port, const uint8_t *data,
                            size_t len)
{
    (void)s; (void)host; (void)port; (void)data; (void)len;
    return -1;
}

#endif

/* The client's socket has room for the reply that waited: it goes now, and what waited behind it —
 * the rest of the node's stream on the REALITY plane, the session's channel on the Hysteria2 plane —
 * follows until everything has gone or the socket is full again. -1 when the session ends. */
static int udp_reply_ready(lc_loop *l, session *s)
{
    lc_loop_del(l, s->reply_wait_fd);
    close(s->reply_wait_fd);
    s->reply_wait_fd = -1;

#if LC_HYSTERIA
    if (s->hy_h != 0) {
        int out = reply_socket_for(s, NULL, 0);
        if (out >= 0 && s->reply_held != NULL) {
            int r = hy_reply(s, out, s->reply_held, s->reply_held_len);
            if (r < 0)
                return -1;
            if (r > 0)
                return 0;
        }
        free(s->reply_held);
        s->reply_held = NULL;
        hy_link *k = hy_link_of(s);
        if (k != NULL)
            lc_qconn_udp_resume(&k->c, s->hy_h);
        return s->idle_deadline == 0 ? -1 : 0;
    }
#endif

    int rc = flush_datagrams(s);
    if (rc == LC_XUDP_ENDED)
        s->up_eof = 1;
    else if (rc != 0)
        return -1;
    return records_ready(s);
}

/* How long the loop may sleep. The plane's timer when there is one, the caller's patience when
 * there is not — asked through a function so that the loop reads the same in both builds. */
static int hy_wait(int cap)
{
#if LC_HYSTERIA
    /* While it is being built as much as while it carries: ngtcp2 asks for its timer to be honoured
     * during the handshake too, and a loop that slept a second between retransmits would turn a
     * lost Initial into a lost second. */
    if (hy.link->up || hy.pending != 0)
        cap = lc_qconn_timeout(&hy.link->c, cap);
    /* And every connection let go of that still carries: each has its own timers. */
    for (unsigned i = 0; i < hy.nleft; i++)
        cap = lc_qconn_timeout(&hy.left[i]->c, cap);
    if (hy_again())
        return 0;
#endif
    /* AND A SESSION WAITING OUT THE INTERVAL BETWEEN TWO DIALS HAS NO DESCRIPTOR TO BE WOKEN BY.
     * Without this the wait would be the reference's 200 ms rounded up to whatever the loop happens
     * to sleep — a second, most of the time — which is a different interval than the one copied
     * from retry.go, and on a client that is quiet it would be five times too long. */
    /* And a request waiting on its client, whose half second ends with nothing to wake the loop: a
     * timeout honoured at the next idle tick instead would be up to a second and a half, where the
     * reference's timer fires at 500 ms. The same for the ActivityTimer's checks, whose one-second
     * forms are the ones a late tick would stretch. */
    for (unsigned i = 0; i < sessions_cap; i++) {
        const session *s = sessions[i];
        if (s == NULL)
            continue;
        uint64_t at;
        if (s->closing) {
            if (s->close_by == 0)
                continue;
            at = s->close_by;
        } else if (s->st == ST_REDIAL)
            at = s->redial_at;
        else if (s->st == ST_OPEN && s->request_due && s->up_n == 0u)
            at = s->request_by;
        else if (s->st == ST_OPEN && s->hy_h == 0 && s->act_ms != 0u)
            at = s->act_next;
        /* Spider retry belongs to fetch_wait in the consumer worker. Its eventfd wakes this
         * loop on progress; a stale copy of an expired retry must not force zero-timeout polls. */
        /* And a connect's clock: the sixteen seconds, and for a dial to a name each address's share
         * and the fallback's 300 ms, which a tick up to a second late would turn into a different
         * dial than Go's. */
        else if (s->st == ST_CONNECTING)
            at = s->deadline;
        else
            continue;
        uint64_t now = lc_now_ms();
        int      in  = at > now ? (int)(at - now) : 0;
        if (in < cap)
            cap = in;
    }
    if (udp_checker.running) {
        uint64_t now = lc_now_ms();
        int      in  = udp_checker.next > now ? (int)(udp_checker.next - now) : 0;
        if (in < cap)
            cap = in;
    }
    /* And the listener resting after running out of descriptors — see accept_exhausted. */
    if (listen_resume_at != 0u) {
        uint64_t now = lc_now_ms();
        int      in  = listen_resume_at > now ? (int)(listen_resume_at - now) : 0;
        if (in < cap)
            cap = in;
    }
    /* AND THE POOL'S DIALLERS, for the same reason: a sleep that ends has no descriptor to wake the
     * loop, and a dial that could not begin is made again on the very next turn. */
    if (spare.started) {
        if (spare.retry_now)
            return 0;
        uint64_t now = lc_now_ms();
        for (unsigned i = 0; i < spare.sleeping; i++) {
            int in = spare.wake[i] > now ? (int)(spare.wake[i] - now) : 0;
            if (in < cap)
                cap = in;
        }
    }
    return cap;
}

/* The session a datagram belongs to, or NULL.
 *
 * Keyed by the client's address, which is what a datagram carries instead of a connection — and, on
 * the Hysteria2 plane, by the destination as well, because the two references do not agree and each
 * plane follows its own.
 *
 *   REALITY. The session belongs to the CLIENT and carries every address it talks to. That is
 *   possible because a Keep frame names its own destination
 *   (vendor/Xray-core/common/xudp/xudp.go:117-121), so one stream carries them all and each reply
 *   says which it came from — which is what XUDP is for.
 *
 *   HYSTERIA2. The session is a PAIR. The reference's transparent mode takes one (src, dst) pair at
 *   a time and opens a whole client session for it — `newPair` calls `r.HyClient.UDP()`
 *   (vendor/hysteria/app/internal/tproxy/udp_linux.go:46-64) — and its forwarder does the same per
 *   listener. The node then opens one socket per session
 *   (vendor/hysteria/core/server/udp.go:309-340), so the far end sees a different source port per
 *   destination: an endpoint-dependent mapping, which is the mapping games and calls fail on.
 *
 * That difference was measured on both sides rather than read: test/hystand/udpshape.sh against the
 * reference server, and tools/natshape through the live node, which answered with one node port for
 * two destinations while this client carried them in one session. Matching the reference here is
 * the maintainer's decision of 16 September, taken knowing what the mapping costs.
 *
 * A linear walk over the whole table, once per packet rather than once per byte. The table has no
 * ceiling any more (see `sessions`), so a box carrying thousands of connections pays for it here. */
static session *udp_session_for(const struct sockaddr_storage *peer, socklen_t len,
                                const char *host, uint16_t port)
{
    for (unsigned i = 0; i < sessions_cap; i++) {
        session *s = sessions[i];
        if (s == NULL || !s->is_udp || s->closing || s->peer_len != len ||
            memcmp(&s->peer, peer, len) != 0)
            continue;
        if (hy.on) {
            /* A pair, and a session holds exactly one destination on this plane — so a datagram for
             * another one belongs to another session, and gets one made for it. */
            if (s->dests == NULL || s->dest_count != 1u || s->dests[0].port != port ||
                strcmp(s->dests[0].host, host) != 0)
                continue;
        }
        return s;
    }
    return NULL;
}

/* The UDP inbound's checker pass, when one is due: see UDP_CHECK_MS. A pass that starts with no
 * datagram session stops the checker; any other closes every session quiet for more than two minutes
 * and waits another minute. The pool's waiting requests count, because the reference's connection
 * exists from the first datagram whether or not an outbound has taken it. */
static void udp_checker_pass(lc_loop *l, uint64_t now)
{
    if (!udp_checker.running || now < udp_checker.next)
        return;
    unsigned held = 0;
    for (unsigned i = 0; i < sessions_cap; i++) {
        const session *s = sessions[i];
        if (s != NULL && !s->closing && s->is_udp && !s->is_spare)
            held++;
    }
    if (held == 0u) {
        udp_checker.running = 0;
        return;
    }
    uint64_t now_s = now / 1000u;
    for (unsigned i = 0; i < sessions_cap; i++) {
        session *s = sessions[i];
        if (s != NULL && !s->closing && s->is_udp && !s->is_spare &&
            now_s - s->udp_seen_s > UDP_IDLE_S)
            session_close(l, s);
    }
    udp_checker.next = now + UDP_CHECK_MS;
}

/* An attempt's connect ran out of its sixteen seconds: the reference's net.Dialer timing out, which
 * its retry takes like any other failure. Said the same way whether the node is an address or a
 * name. */
static void note_connect_timeout(const session *s)
{
    stats.gave_up_connecting++;
    if (s->is_spare)
        note("a connect to the node took over %u ms, for a spare tunnel", CONNECT_ATTEMPT_MS);
    else if (log_per_connection())
        note("a connect to the node took over %u ms, dialling for %s:%u", CONNECT_ATTEMPT_MS,
             s->target_host, s->target_port);
    else
        note("a connect to the node took over %u ms", CONNECT_ATTEMPT_MS);
}

static int advance_handshake(lc_loop *loop, session *s);
static int hs_pump(session *s);

/* A dial to a node given by name has moved: its descriptor woke, or one of its clocks is due.
 * 0 while it goes on; 1 when it has connected and the session is shaking hands, as a connect to an
 * address that reports writable goes on to; -1 when the attempt has failed, which the caller hands
 * to dial_failed like every other failed attempt. */
static int dial_turn(lc_loop *l, session *s)
{
    int fd = lc_dial_step(s->dial, lc_now_ms());
    if (fd == LC_DIAL_PENDING) {
        s->deadline = lc_dial_wake(s->dial);
        return 0;
    }
    if (fd < 0) {
        if (lc_dial_timed_out(s->dial)) {
            note_connect_timeout(s);
        } else {
            stats.dial_failed++;
            note("cannot reach the node: %s", lc_dial_why(s->dial));
        }
        return -1;
    }
    /* Connected: the dial's descriptor goes, the connection takes its place on the loop. */
    dial_drop(l, s);
    s->up_fd = fd;
    if (lc_loop_add(l, fd, 0, &s->up_tag) != 0)
        return -1;
    s->st = ST_HANDSHAKE;
    s->deadline = 0;
    return advance_handshake(l, s) != 0 ? -1 : 1;
}


/* Runs every clock a session has: the wait between dial attempts, the connect of one attempt
 * (CONNECT_ATTEMPT_MS, Xray's sixteen seconds), the VLESS request's wait for the client's first
 * bytes, the activity timer of an open connection, the datagram sessions' idle check and the
 * spider's backoff. A handshake has none, and neither does a stream waiting for its node's answer —
 * the reference bounds neither (see CONNECT_ATTEMPT_MS and hy_start).
 *
 * ⚠️ "ONE THAT HAS NOT FINISHED CONNECTING OR SHAKING HANDS WITHIN FIFTEEN SECONDS IS NEVER GOING
 * TO" stood here until 2026-09-27, from the days of CONNECT_MS, which bounded the whole dial and the
 * handshake with it. Both halves went when that constant did. */
static void sessions_expire(lc_loop *l)
{
    uint64_t now = lc_now_ms();
    if (!hy.on)
        udp_checker_pass(l, now);
    for (unsigned i = 0; i < sessions_cap; i++) {
        session *s = sessions[i];
        if (s == NULL)
            continue;
        if (s->closing) {
            if (s->close_by != 0 && now >= s->close_by)
                session_close(l, s);
            continue;
        }

        /* THE WAIT AFTER AN ATTEMPT, WHICH UPSTREAM SPENDS IN time.Sleep. It has no descriptor to be
         * woken by, so this is what wakes it; hy_wait keeps the loop from sleeping past the moment,
         * which is why the interval is honoured rather than rounded up to the next tick.
         *
         * After the fifth attempt the wait is the retry's last sleep, and what follows it is the
         * request failing — "failed to find an available destination" — and the client's connection
         * closing. An attempt that cannot even be started is a failed attempt like the rest. */
        if (s->st == ST_REDIAL) {
            if (now < s->redial_at)
                continue;
            if (s->dial_try >= DIAL_TRIES) {
                stats.gave_up_handshake++;
                if (log_per_connection())
                    note("the node could not be reached in %u attempts, dialling for %s:%u",
                         DIAL_TRIES, s->target_host, s->target_port);
                else
                    note("the node could not be reached in %u attempts", DIAL_TRIES);
                session_close(l, s);
                continue;
            }
            if ((dial_node(l, s, spare.table, spare.table_len, spare.sni, spare.reality,
                           spare.node) != 0 &&
                 dial_failed(l, s) != 0) ||
                session_rearm(l, s) != 0)
                session_close(l, s);
            continue;
        }

        if (s->st == ST_OPEN) {
            /* The request's half second, spent: `buf.ErrReadTimeout`, and the header goes without
             * the client's bytes. See request_write. */
            if (s->request_due && s->up_n == 0u && now >= s->request_by) {
                if (request_timeout(s) != 0 || session_rearm(l, s) != 0)
                    session_close(l, s);
                continue;
            }
            /* The Hysteria2 plane: a datagram session goes after the node's own idle time, and a stream
             * when a side closes it — see hy_pump. */
            if (s->hy_h != 0) {
                if (s->is_udp && now >= s->idle_deadline)
                    session_close(l, s);
                continue;
            }
            /* The REALITY plane: the ActivityTimer, which is the only clock an open session has. */
            if (act_fired(s, now))
                session_close(l, s);
            continue;
        }

        /* Neither a pooled connection nor a request waiting for one is on a clock this sweep keeps.
         * The pooled one's stamp is read by the taker alone (spare_take), as in the reference, and the
         * request's receive has no timeout there either. */
        if (s->st == ST_SPARE || s->st == ST_POOLWAIT)
            continue;

        /* A REALITY handshake has no clock of its own — see CONNECT_ATTEMPT_MS — and a session
         * between attempts is woken by redial_at above. Nor does anything on the Hysteria2 plane: a
         * stream waits for the node's reply as long as the connection lives
         * (vendor/hysteria/core/client/client.go:216, ReadTCPResponse with no deadline), and a request
         * waits for the connection it asked for — see hy_start. */
        if (s->st == ST_HANDSHAKE || s->st == ST_HYWAIT)
            continue;
        /* The fetch after a stranger's answer has one clock, and only while RoundTrip waits out a
         * retry's backoff (lc_spider_fetch_deadline) — no deadline of the session's own; see the
         * gravestone of SPIDER_MS. */
        if (s->st == ST_SPIDER) {
            /* fetch_wait owns the monotonic retry deadline and wakes the worker at it. */
            continue;
        }
        /* Nor has the fetch after a stranger's answer: ST_SPIDER carries no deadline at all
         * now, and falls out here on the line below — see the gravestone of SPIDER_MS. */
        if (s->deadline == 0u || now < s->deadline)
            continue;

        /* ⚠️ THE NODE IS WHAT WE GAVE UP ON; THE DESTINATION IS ONLY WHY WE WERE DIALLING, so the
         * destination is named only behind log_per_connection. Read off the live router 2026-08-30:
         * 555 give-ups naming 212 distinct destinations — a list of where the household went, in a
         * system log — and an hour spent on Opera's load balancers because `giving up on
         * 185.26.182.106:443` reads as "that address is unreachable", when every state that reaches
         * this sweep is between us and the node and the destination has not yet been asked for
         * anything. A spare has no destination at all. See note_connect_timeout. */
        if (s->st == ST_CONNECTING && s->dial != NULL) {
            /* A dial to a name has clocks of its own inside the sixteen seconds — each address's
             * share and the fallback's 300 ms — and says itself which of them this was. */
            int r = dial_turn(l, s);
            if (r == 0)
                continue;
            if ((r < 0 && dial_failed(l, s) != 0) || session_rearm(l, s) != 0)
                session_close(l, s);
            continue;
        }
        if (s->st == ST_CONNECTING) {
            note_connect_timeout(s);
            if (dial_failed(l, s) != 0 || session_rearm(l, s) != 0)
                session_close(l, s);
            continue;
        }

    }
}

/* Opens the pipe the moment direct copy is announced, and not before: a connection that never gets
 * there — anything not carrying TLS inside — never pays for it. */
static int splice_arm(session *s)
{
    int fds[2];
    /* Close-on-exec because a descriptor carrying someone's traffic has no business surviving into
     * a program this one might one day start. */
    if (pipe2(fds, O_CLOEXEC) != 0)
        return -1;
    s->pipe_rd = fds[0];
    s->pipe_wr = fds[1];
    if (lc_set_nonblocking(s->pipe_rd) != 0 || lc_set_nonblocking(s->pipe_wr) != 0)
        return -1;
    /* Go's newPipe: the read end, maxSpliceSize, and the error ignored — "a smaller buffer size will
     * work, although it will require more system calls" (GOROOT/src/internal/poll/splice_linux.go:
     * 230-235). */
    (void)fcntl(s->pipe_rd, F_SETPIPE_SZ, SPLICE_MAX);
    return 0;
}

/* Moves the handshake as far as it will go on what has arrived, and sends whatever it produces.
 * Returns -1 when the connection is finished with — including the case that matters most, a
 * handshake that completed against something which is not our node. */
static int advance_handshake(lc_loop *loop, session *s)
{
    for (;;) {
        lc_client_progress p = lc_client_hs_step(s->hs, &s->cl);

        if (p == LC_HS_FAILED) {
            /* THE ALERT THE REFUSAL OWES, WHICH THIS PROGRAM NEVER SENT.
             *
             * tls/client.c chooses an alert for every way a handshake can be refused, and says why
             * it matters: a prober that answers our hello with an anomalous flight tells a Go
             * client from this one by whether seven bytes come back or the socket merely dies.
             * That choosing was complete and INERT here — the alert was recorded into the handshake
             * struct, the struct was freed, and nothing ever put it on the wire. The one program
             * that did was lc-probe, through lc_client_hs_run, which is also the program every
             * hardware check was run with; the suites stop at "the right alert is pending". So the
             * distinguisher the alerts exist to remove was present in the only binary that ships.
             *
             * Queued rather than written, and that is not tidiness: our hello may still be sitting
             * in this queue on a slow socket, and a direct write would put the alert in front of
             * it. Flushed once, non-blocking, and dropped if it will not go — the peer has just
             * been refused, and a write that fails here must not replace the reason. */
            if (s->up_fd >= 0) {
                uint8_t arec[LC_CLIENT_ALERT_MAX];
                size_t  alen;
                /* Flushed BEFORE the push as well as after: on a slow socket the hello may still be
                 * queued, and the alert only fits behind it if there is room. Both flushes are best
                 * effort and neither can change why the handshake ended. Round until none is
                 * owed: each call is one of the reference's writes — see
                 * lc_client_hs_alert_record. */
                while ((alen = lc_client_hs_alert_record(s->hs, arec, sizeof arec)) > 0) {
                    (void)q_flush(&s->to_up, s->up_fd);
                    if (q_push(&s->to_up, arec, alen) == 0)
                        (void)q_flush(&s->to_up, s->up_fd);
                }
            }

            /* A failed attempt, which the caller hands to dial_failed: the reference's Dial returns
             * this as an error and its retry dials again — and leaves the socket to the collector,
             * which closes it at its next cycle. So does this, through the model of it (gcemu). */
            s->gc_park = 1;
            note("tunnel refused while %s: %s", s->cl.stage, lc_client_hs_error(s->hs));
            return -1;
        }

        if (p == LC_HS_WANT_WRITE) {
            size_t         n = 0;
            const uint8_t *out = lc_client_hs_out(s->hs, &n);
            /* ONE FLIGHT, ONE WRITE, AND IT LEAVES BEFORE ANYTHING ELSE IS WRITTEN.
             *
             * The reference writes its ClientHello unbuffered, and the second flight — the dummy
             * ChangeCipherSpec and Finished — into a buffer it flushes in one call at the end of the
             * handshake (vendor/utls/handshake_client_tls13.go:136-166). The VLESS request is a later
             * Write, after Dial has returned. This queued the flight and then sealed the request into
             * the same queue, so both left in one write and, whenever the request was small, in one
             * segment: CCS, Finished and the first application record together, where the reference's
             * last handshake segment ends at the Finished. Straight to the socket now, like every
             * other write — see conn_write.
             *
             * Counted into bytesSent, because Go counts it: see tls_write. */
            if (conn_write(s, out, n) != 0)
                return -1;
            s->tls_bytes_sent += n;
            lc_client_hs_out_taken(s->hs, n);
            /* Round again: the machine may have more to say before it needs an answer. */
            continue;
        }

        /* What the machine waits for may be in hand already — a read brings what the reference's
         * would, which can be more than one record. */
        if (p == LC_HS_WANT_READ) {
            int fed = hs_pump(s);
            if (fed < 0)
                return -1;
            if (fed > 0)
                continue;
            return 0;
        }

        /* TLS 1.2, when the server chose it: the reader's rules follow (tls/post.c). */
        s->post.tls12 = s->cl.rd.tls12;

        /* What the server's Finished had behind it in its record goes on as the start of the next
         * handshake message, as c.hand does in the reference — see lc_client_hs_leftover. */
        {
            size_t         left = 0;
            const uint8_t *rest = lc_client_hs_leftover(s->hs, &left);
            if (left > 0) {
                s->post.hand = malloc(left);
                if (s->post.hand == NULL)
                    return own_failure(s);
                memcpy(s->post.hand, rest, left);
                s->post.hand_len = left;
            }
        }

        /* Complete. And complete is not the same as ours: a REALITY server that took us for a
         * stranger produces a perfectly good handshake with the donor site behind it, so carrying
         * traffic over it would send the user's data to a web site instead of the node. */
        if (!s->cl.reality_verified) {
#if LC_SPIDER_PROFILE
            uint64_t profile_handoff_begin = spider_profile_now();
#endif
            /* NO DEVICE-WIDE PAUSE, WHICH IS WHAT THE REFERENCE ALSO DOES NOT HAVE.
             *
             * `backoff_failed(1)` stood here and armed a process-global ladder from five seconds to
             * five minutes, during which EVERY new session on the device was refused before a socket
             * existed. The comment called it "a configuration that will not start working by
             * itself", which is true of a wrong key and untrue of the cases that actually produce a
             * stranger: a clock the router has not yet corrected, a short id rotated on the node, a
             * middlebox in the way for a minute.
             *
             * Upstream returns the failure to the ONE request and suppresses nothing:
             *
             *     time.Sleep(time.Duration(crypto.RandBetween(config.SpiderY[8], config.SpiderY[9])) * time.Millisecond)
             *     return nil, errors.New("REALITY: processed invalid connection")
             *                            (vendor/Xray-core/transport/internet/reality/reality.go:297-298)
             *
             * — and that sleep is zero unless a configuration asks otherwise. The next dial goes out
             * at whatever rate the client behind it dials.
             *
             * The difference was not merely a lost minute. An adversary who can make the node answer
             * as a stranger ONCE sees a real Xray client keep opening handshakes and sees this one go
             * completely silent for up to five minutes — a device-level behaviour that no amount of
             * byte-level fidelity repairs, and that is induced rather than merely observed. */
            note("tunnel refused: REALITY not authenticated — %s",
                 s->cl.reality_note[0] ? s->cl.reality_note : "no certificate seen");
#if LC_SPIDER_PROFILE
            uint64_t profile_logged = spider_profile_now();
#endif

            /* AND THE CONNECTION DOES NOT END HERE, AND NEITHER DOES THE REQUEST.
             *
             * The reference sets its spider going on this connection in a goroutine that keeps it —
             * "Do not close the connection" — and then returns the dial as failed, so its retry dials
             * again at once (vendor/Xray-core/transport/internet/reality/reality.go:207-299). Both
             * happen: the node sees the fetch it served continue on this connection, and a fresh
             * attempt for the same request arrive beside it. This held the request in ST_SPIDER until
             * the fetch was over and then closed it, which is one attempt where the reference makes
             * up to five.
             *
             * So the connection moves to a session of its own and this one goes back to dial_failed
             * through the caller. A table with no slot for it is the one case where the fetch cannot
             * be made; the connection then goes with the attempt, and the request still dials again. */
            session *sp = session_new();
            if (sp == NULL)
                return -1;
#if LC_SPIDER_PROFILE
            sp->spider_profile_logged = profile_logged;
            sp->spider_profile_allocated = spider_profile_now();
#endif
            sp->up_fd = s->up_fd;
            s->up_fd = -1;
            sp->cl = s->cl;
            memset(&s->cl, 0, sizeof s->cl);
            sp->post.hand = s->post.hand;
            sp->post.hand_len = s->post.hand_len;
            sp->post.tls12 = s->post.tls12;
            s->post.hand = NULL;
            s->post.hand_len = 0;
            sp->sni = s->sni;
            sp->tls_records_sent = s->tls_records_sent;
            sp->tls_bytes_sent = s->tls_bytes_sent;
            sp->st = ST_SPIDER;
            /* And what the handshake's reads brought past it, with the shape of the reference's
             * buffer it lies in: the reference's spider reads on through the same tls.Conn. */
            sp->rin = s->rin;
            if (rx_fit(sp) != 0) {
                session_close(loop, sp);
                return -1;
            }
            memcpy(sp->rx, s->rx, s->rx_len);
            sp->rx_len = s->rx_len;
            s->rx_len = 0;
            memset(&s->rin, 0, sizeof s->rin);
#if LC_SPIDER_PROFILE
            sp->spider_profile_transferred = spider_profile_now();
#endif
            /* AND IT IS NOT GIVEN A CLOCK, which is the reference's behaviour and, since 16
             * September, this client's by decision of the maintainer.
             *
             * What stood here was `sp->deadline = lc_now_ms() + SPIDER_MS` with three seconds and a
             * note that the reference bounds this with a garbage collector. The stand
             * tools/vendorcap/spiderlife measured both and neither half of that was right: the
             * reference closes NOTHING — its own comment says `// Do not close the connection`, and
             * all five of its connections were still open when the watch ended — while this client
             * was closing at END_STREAM, ten to twenty milliseconds in, nowhere near the three
             * seconds. A bound nobody else has is a shape on the wire: one client closes first,
             * always at the same point, and the other never closes at all.
             *
             * So the session now lives until the FAR END ends it, and what that costs is real,
             * measured and accepted: a descriptor and a whole session — about fifty kilobytes of
             * inline buffers — per stranger connection, held for as long as the site holds the
             * connection open. A refused request makes FIVE of them, and the session table has no
             * ceiling of its own (see `sessions`): against a node that answers as a stranger to
             * everything, this client goes on dialling until the memory guard refuses, where the
             * reference goes on allocating until the machine does. Both keep the connection; only
             * the way they run out differs, and ours is the one that says so in the log. */
            sp->deadline = 0;
            /* The descriptor was registered for the session it came from; the loop is told whose it
             * is now. Nothing of that session's is pending for it in this batch: epoll reports a
             * descriptor once per wait, and this is its report. */
            if (lc_loop_mod(loop, sp->up_fd, 0u, &sp->up_tag) != 0) {
                session_close(loop, sp);
                return -1;
            }

            lc_browser b;
#if LC_SPIDER_PROFILE
            sp->spider_profile_base = profile_handoff_begin;
            sp->spider_profile_handoff = spider_profile_now();
#endif
            /* Anchored, so that a router reconnecting every few seconds does not present a fleet of
             * different Chromes to the node and to the site it masquerades as. */
            sp->fetch = lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0
                            ? lc_spider_fetch_new(sp->sni, &b)
                            : NULL;
#if LC_SPIDER_PROFILE
            sp->spider_profile_fetch = spider_profile_now();
#endif
            /* Submit initial protocol writes before arming node reads. TLS stays loop-owned;
             * HTTP/2 operations are serialized across the loop and the Do worker. */
            if (sp->fetch == NULL || spider_start(loop, sp) != 0 || spider_pump(sp) != 0 ||
                session_rearm(loop, sp) != 0)
                session_close(loop, sp);
            return -1;
        }

        /* WHICH CIPHER THE NODE CHOSE, ONCE PER PROCESS, which the Hysteria2 plane has always said
         * and this one never did.
         *
         * The asymmetry was not harmless. On 2026-09-19 the AES-GCM ceiling measured by test/bench
         * was reasoned onto a tunnel without anybody being able to read what it had negotiated; the
         * plane that DOES print it turned out to be running ChaCha20-Poly1305, and the arithmetic
         * had agreed with the observed processor share by coincidence. Half a line here makes that
         * unguessable — and it has to be read rather than deduced, because the SERVER picks the
         * suite (vendor/REALITY/handshake_server_tls13.go:277-280 prefers AES-GCM when the client's
         * list does and the box has the instructions for it), so this side cannot know it from its
         * own configuration.
         *
         * Once, not per tunnel: this plane opens one per connection, and the answer cannot differ
         * between them while the node and the hello stay the same. */
        static int suite_said = 0;
        if (!suite_said) {
            suite_said = 1;
            note("the node chose %s", lc_aead_alg_name(lc_aead_alg_of(&s->cl.rd.aead)));
        }

        lc_client_hs_free(s->hs);
        s->hs = NULL;

        /* A tunnel dialled ahead of need stops exactly here, and that this is the natural place to
         * stop is the whole of why the feature is cheap: everything above is the cost of opening a
         * tunnel and none of it names a destination. What is left — the VLESS request and the
         * client's first bytes — is the part that does, and it waits for somebody to ask.
         *
         * Not counted as an open: note_open_wait measures what a PERSON waited, and nobody is
         * waiting on this one. It is measured in spare_bind instead, from the moment a person
         * actually arrives. */
        /* Records the last read brought past the handshake are the next state's, taken as it takes
         * them — see hs_pump. */
        if (s->is_spare) {
            s->st = ST_SPARE;
            /* The stamp the reference puts on it as it hands it to the channel (vless/outbound/outbound.go:170). */
            s->deadline = lc_now_ms() + SPARE_EXPIRE_MS;
            return spare_records(s);
        }

        s->st = ST_OPEN;
        note_open_wait(s);
        /* Whatever the client said while the tunnel was being built goes out now, in order and
         * ahead of anything it says next — the stream's first bytes with the request, and on a
         * datagram session each datagram under its OWN destination. See request_write. */
        int rs = request_start(s);
        if (rs == 0 && s->rx_len > 0u)
            rs = records_ready(s);
        return rs;
    }
}

/* Reads what the site sends on a stranger's connection and hands it to the fetch — the reference's
 * HTTP/2 client — writing whatever the fetch answers: SETTINGS and PING acknowledged, the window
 * handed back as the page is read, a redirect followed. See reality/fetch.c.
 *
 * Returns -1 only when the CONNECTION is finished with — the far end closed it, the socket failed,
 * or x/net would have dropped it over what the site sent. The end of the page is not the end of the
 * connection: the reference keeps it and so does this.
 *
 * Records are assembled in the session's own buffer, the same one the ST_OPEN path uses and which
 * is idle here for the same reason it is idle during the handshake. A record may arrive in pieces
 * and usually does, and a frame may span records — the fetch puts frames together itself; what used
 * to stand here walked each record's frames on their own and lost every frame that did not end in
 * the record it began in, which with DATA frames of sixteen kilobytes in records of sixteen is most
 * of a page.
 *
 * Drain available bytes while the independent Do/request tasks run, up to SPIDER_READS for
 * fairness to the other sessions. Readiness may be stale and a read may be interrupted: node_fill
 * returns 0 for those waits and -2 for actual EOF. Go's FD.Read in internal/poll/fd_unix.go waits
 * through EAGAIN and EINTR too; neither closes the connection. */
#define SPIDER_READS 16u

/* The read failed — see lc_spider_fetch_lost: what arrived before it is settled first, so that a page
 * the site finished and then closed after is harvested, as the reference's io.ReadAll harvests it;
 * then the streams it had not finished are aborted with the connection. */
static int spider_lost(session *s)
{
    if (!s->spider_peer_lost) {
        s->spider_peer_lost = 1;
        lc_spider_fetch_loss_pending(s->fetch);
    }
    /* An active Do still settles its final body before EOF. Once it has
     * returned, the retained readLoop must make that progress itself. */
    return lc_spider_fetch_done(s->fetch) ? spider_drain(s) : 0;
}

static int spider_pump(session *s)
{
    /* What is in hand is taken first — a spider that has just been given its connection may hold
     * records the handshake's reads brought — and then one read of the reference's size at a
     * time, each followed by what it made whole. */
    for (unsigned reads = 0;; reads++) {
        for (;;) {
            /* Even complete records already in rawInput belong beyond handleKeyUpdate's blocking
             * reply Write. Leave them intact until the write side resumes this pump. */
            if (s->ku_owed > 0u || s->spider_ku_pending ||
                !lc_spider_fetch_read_ready(s->fetch))
                break;
            if (s->rx_len < LC_REC_HEADER)
                break;
            size_t body = (size_t)s->rx[3] << 8 | s->rx[4];
            if (node_header(s, s->rx) != 0)
                return spider_lost(s);
            if (s->rx_len < LC_REC_HEADER + body)
                break;

            static uint8_t plain[LC_REC_MAX_WIRE12];
            size_t         plain_len = 0;
            uint8_t        inner = 0;
            int rv = node_open(s, s->rx, LC_REC_HEADER + body, plain, sizeof plain, &plain_len,
                               &inner);
            rx_take(s, LC_REC_HEADER + body);
            if (rv != 0)
                return spider_lost(s);
            /* A session ticket, an empty record, the site's close_notify: the same tls.Conn reads
             * these for the reference's spider as for its stream — see node_record. */
            rv = node_record(s, plain, plain_len, inner);
            if (rv == 0)
                continue;
            if (rv != NODE_DATA)
                return spider_lost(s); /* the far end finished, or was refused */
            int rc = lc_spider_fetch_feed(s->fetch, plain, plain_len);
            if (rc != 0)
                return spider_after(s, rc);
            if (spider_drain(s) != 0)
                return -1;
        }

        if (reads == SPIDER_READS)
            break;
        /* A KeyUpdate in what was just read, whose answer found no room: no more is read until it
         * has gone — see node_key_update. */
        if (s->ku_owed > 0u || s->spider_ku_pending || !lc_spider_fetch_read_ready(s->fetch))
            break;
        int got = node_fill(s, node_want(s));
        if (got == 0)
            break;
        if (got < 0)
            return spider_lost(s); /* the far end finished, or the socket did */
    }
    /* The consumer handles protocol transitions and its own monotonic retry deadline. */
    return 0;
}

static int spider_read(session *s)
{
    return spider_pump(s);
}

/* The HTTP/2 readLoop is independent of request/Flush writers (pinned x/net
 * transport.go:554, :1869; uTLS Conn.Read holds only c.in at conn.go:1391).
 * One socket event may report both directions: completing a Write must not
 * discard its READ bit. The pump still respects its own cc.wmu and KeyUpdate
 * barriers. This does not order an independent Body.Close behind new input. */
static int spider_socket_event(session *s, unsigned events)
{
    int failed = 0;
    if (events & LC_EV_WRITE) {
        failed = q_flush(&s->to_up, s->up_fd) != 0;
        if (!failed)
            failed = spider_write_complete(s) != 0;
        if (!failed)
            failed = ku_settle(s) != 0;
        if (!failed && q_pending(&s->to_up) == 0) {
            failed = spider_write_complete(s) != 0 || spider_drain(s) != 0;
            if (!failed && !s->spider_peer_lost && s->ku_owed == 0u &&
                !s->spider_ku_pending && s->rx_len > 0u)
                failed = spider_pump(s) != 0;
            if (!failed && s->spider_end && q_pending(&s->to_up) == 0)
                failed = 1;
        }
    }
    if (!failed && (events & LC_EV_READ) && !s->spider_peer_lost)
        failed = spider_read(s) != 0;
    return failed ? -1 : 0;
}

/* The handshake's records, out of the session's buffer, as far as it holds what the machine asks
 * for: a record's header, and — once the machine has judged it and asks for the body — the body,
 * the record then taken from the front. 1 when something was given, 0 when what is asked for has
 * not all come, -1 when the machine would not take it.
 *
 * The machine asks for exact counts, which is what keeps a record from running into the next one;
 * the reads that fill the buffer are the reference's, which is what leaves in the socket what the
 * reference leaves. Whatever the last read brought past the handshake stays at the front for the
 * state that comes next — see advance_handshake. */
static int hs_pump(session *s)
{
    size_t want = lc_client_hs_want(s->hs);
    if (want == 0u || s->rx_len - s->hs_fed < want)
        return 0;
    /* The machine takes exactly what it asked for, but the check is here rather than assumed:
     * bytes silently dropped between the buffer and the handshake would show up as a transcript
     * that does not verify, several layers away from the cause. */
    if (lc_client_hs_feed(s->hs, s->rx + s->hs_fed, want) != want)
        return -1;
    s->hs_fed += want;
    if (s->hs_fed > LC_REC_HEADER && s->hs_fed == node_want(s)) {
        rx_take(s, s->hs_fed);
        s->hs_fed = 0;
    }
    return 1;
}

/* One read for the handshake, of the reference's size, towards what the machine waits for: the
 * header at the front, or once it has the header, the whole record. Nothing when the machine is
 * writing, or has what it asked for in hand already. */
static int handshake_read(session *s)
{
    size_t want = lc_client_hs_want(s->hs);
    if (want == 0u)
        return 0;
    int got = node_fill(s, s->hs_fed == 0u ? (size_t)LC_REC_HEADER : s->hs_fed + want);
    if (got == -2) {
        /* A node that closes mid-handshake is REALITY's way of saying it wants nothing to do with
         * us, so it is reported as a verdict rather than as a broken pipe. */
        note("tunnel refused: the node closed while %s", s->cl.stage);
        return -1;
    }
    return got < 0 ? -1 : 0;
}

/* True once both of the reference's copies have ended — `task.Run` returning nil — which on the REALITY
 * plane is the one way a session ends without its timer. Each copy is marked ended only once what it
 * carried has been written; see the end of the event turn.
 *
 * ⚠️ A DATAGRAM SESSION WAS DONE WHEN THE NODE LET GO OF IT, and a stream when both sides had said EOF.
 * Neither is the reference: when the downlink copy ends the uplink copy is still waiting on its
 * reader, and the connection lasts until that ends too or the timer — UplinkOnly, one to two seconds —
 * ends it. The Hysteria2 plane never reaches here; hy_pump ends its streams. */
static int session_done(const session *s)
{
    return s->hy_h == 0 && s->req_done && s->resp_done;
}

static void usage(void)
{
    fprintf(stderr,
            "usage: lc-tunnel TABLE.fpt NODE PORT SNI PBK SHORTID UUID LISTEN [options]\n"
            "       lc-tunnel -H NODE PORTS SNI AUTH OBFS LISTEN [options]\n"
            "       lc-tunnel --planes            which planes this build carries, one per line\n"
            "  --check-config                    validate this command without starting a tunnel\n"
            "\n"
            "  AUTH, OBFS and UUID take @FILE as well as a literal; OBFS takes - for none.\n"
            "  PORTS on -H is one port, or ports and ranges as hysteria writes them\n"
            "  (20000-30000,40000,41000-42000): with a '-' or a ',' the client moves among them, by\n"
            "  default every half minute. The node keeps one port and needs a redirect to it.\n"
            "  options, on either plane:  -t HOST:PORT   -u PORT[@HOST:PORT]\n"
            "                             -w N|auto  how many copies share the listeners, 1..8,\n"
            "                                   or one per CPU the kernel reports. They split\n"
            "                                   CONNECTIONS between cores, not one download: a\n"
            "                                   single stream stays in one worker.\n"
            "  on the REALITY plane:      -f FLOW\n"
            "                             -P N   Xray's testpre, 0..4, default 0 (off). From the\n"
            "                                    first request on, N connections are kept dialled\n"
            "                                    ahead of need, and every request takes one\n"
            "                                    rather than dialling: good for two minutes after\n"
            "                                    its dial, the next dialled 200 ms after one is\n"
            "                                    taken. Per worker.\n"
            "  on -H:                     -r BYTES_PER_SECOND\n"
            "                             -j SECONDS or MIN-MAX  how often to move, at least 5 —\n"
            "                                        the reference refuses anything shorter; a span\n"
            "                                        draws a fresh interval for every move. Only\n"
            "                                        meaningful with several ports.\n"
            "                             -p SHA256  the node's certificate, hex. REQUIRED — the\n"
            "                                        reference verifies the certificate by default\n"
            "                                        and this cannot, so the pin is the whole of\n"
            "                                        the evidence. `-p -` runs without it, on\n"
            "                                        purpose. Get it with:\n"
            "                                        openssl x509 -outform der | sha256sum\n"
            "                             -g MIN-MAX gecko: cut every handshake packet into 2..8\n"
            "                                        datagrams of these sizes. Only when the node\n"
            "                                        runs it — a node that does answers nothing\n"
            "                                        else, and a node that does not drops these.\n"
            "                                        The reference's own sizes are 512-1200.\n"
            "                             -c on|off  parrot Chrome's QUIC stack, as the reference\n"
            "                                        client does unless told not to. On by\n"
            "                                        default; off is its disableChromeParrot.\n"
            "\n"
            "  exit: 0 carried traffic, 1 the network said no, 2 the command line or the node's\n"
            "        answer means this could never have worked. See src/core/args.h.\n");
    exit(LC_EXIT_CONFIG);
}

/* What this binary can actually do, asked rather than guessed at.
 *
 * The service script has to know before it touches the firewall: `option plane hysteria` on a
 * REALITY-only build is refused by the check below, but that refusal happens after the rules are up,
 * which is a LAN with its port 80 and 443 redirected into a process that exits. One line of output
 * lets the script find out for the price of a fork. */
static void planes(void)
{
    printf("reality\n");
    if (LC_HYSTERIA)
        printf("hysteria\n");
    exit(LC_EXIT_OK);
}

/* Holds the group of workers together, and is the whole of what the parent does once there is more
 * than one.
 *
 * ⚠️ THE PARENT DOES NOT CARRY TRAFFIC, and that is the point rather than a simplification. procd
 * supervises ONE pid. Had the parent been worker number one, a child that died would have left the
 * group quietly smaller — no restart, no log line, a router running on three cores' worth of
 * workers and nobody the wiser until someone counted processes. A parent that only waits can put
 * the dead one back.
 *
 * And it can put it back CLEANLY, which is the second reason for this shape. Re-forking from inside
 * a running event loop would hand the new child a copy of live sessions and a live epoll
 * descriptor. The supervisor never creates either, so a fork from here starts exactly where the
 * first workers started.
 *
 * Shutdown needs no code: procd signals the parent, the parent dies, and every child has
 * PR_SET_PDEATHSIG set, so the kernel takes them with it. The original parent PID is checked after
 * prctl: an orphan can be adopted by a non-init subreaper when the supervisor died before prctl.
 *
 * Returns the worker's index. Only a child ever returns; the parent loops here until it is killed. */
static volatile sig_atomic_t supervisor_usr1;
static volatile sig_atomic_t supervisor_usr2;

static void on_supervisor_signal(int sig)
{
    if (sig == SIGUSR1)
        supervisor_usr1 = 1;
    else if (sig == SIGUSR2)
        supervisor_usr2 = 1;
}

/* How long a worker has to have lived for its crash to be a crash rather than a start that cannot
 * succeed. Not a number of ours: it is the pause procd itself takes between restarts of this service
 * (`respawn 3600 5 0` in package/files/lite-client.init), so a worker dying on start is replaced at
 * the pace the whole service would be — with one worker there is no supervisor and procd does
 * exactly this. */
#define WORKER_RESPAWN_S 5u

static unsigned supervise(unsigned workers, const char *plane)
{
    const pid_t supervisor_pid = getpid();
    pid_t    kids[8];
    uint64_t born_ms[8], retry_ms[8];
    for (unsigned i = 0; i < workers; i++) {
        kids[i] = -1;
        born_ms[i] = 0;
        retry_ms[i] = 0;
    }

    /* ⚠️ WITHOUT THIS, ASKING FOR A SUMMARY KILLED THE TUNNEL. The summary is asked for with
     * `kill -USR1`, and the pid an operator has is the one procd knows — which, with workers, is
     * this process. It installs no handler of its own (main's sigaction runs only in a worker,
     * after this function has returned), so SIGUSR1 took its default action: terminate. The
     * supervisor died, PR_SET_PDEATHSIG took every worker with it, and procd restarted the service.
     * A documented diagnostic that takes the household off the internet.
     *
     * Forwarded rather than merely ignored, because ignoring would leave the operator with no way
     * to reach the workers at all: their pids are in the log and nowhere else. One signal to the
     * pid procd knows now asks every worker, which is what was meant by it in the first place.
     *
     * ⚠️ AND SIGUSR2 THE SAME WAY — this paragraph fixed USR1 and left its twin with the default
     * action while workers were opt-in. Since REALITY forks one worker per CPU by default,
     * `kill -USR2 <pid procd knows>` — the documented way to zero the counters before a measurement
     * — terminated the supervisor, PR_SET_PDEATHSIG took the workers, and procd restarted the
     * service, dropping every connection in the house. test/seam sends it. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_supervisor_signal;
    sigemptyset(&sa.sa_mask);
    struct sigaction original_chld;
    if (sigaction(SIGUSR1, &sa, NULL) != 0 || sigaction(SIGUSR2, &sa, NULL) != 0 ||
        sigaction(SIGCHLD, &sa, &original_chld) != 0) {
        fprintf(stderr, "cannot configure supervisor signals: %s\n", strerror(errno));
        _exit(LC_EXIT_FAILED);
    }
    /* Keep managed signals blocked while inspecting flags/children. pselect
     * atomically unblocks them while waiting, including a signal already pending
     * before the wait. Workers recover their inherited mask and SIGCHLD action. */
    sigset_t managed, original_mask;
    sigemptyset(&managed);
    sigaddset(&managed, SIGUSR1);
    sigaddset(&managed, SIGUSR2);
    sigaddset(&managed, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &managed, &original_mask) != 0) {
        fprintf(stderr, "cannot block supervisor signals: %s\n", strerror(errno));
        _exit(LC_EXIT_FAILED);
    }
    sigset_t wait_mask = original_mask;
    sigdelset(&wait_mask, SIGUSR1);
    sigdelset(&wait_mask, SIGUSR2);
    sigdelset(&wait_mask, SIGCHLD);

    for (;;) {
        int fork_failed = 0;
        uint64_t now = lc_now_ms();
        for (unsigned i = 0; i < workers; i++) {
            if (kids[i] > 0 || now < retry_ms[i])
                continue;
            pid_t pid = fork();
            if (pid == 0) {
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) {
                    fprintf(stderr, "cannot set parent-death signal for worker %u of %u: %s\n",
                            i + 1u, workers, strerror(errno));
                    _exit(LC_EXIT_FAILED);
                }
                if (getppid() != supervisor_pid)
                    _exit(0);
                if (sigaction(SIGCHLD, &original_chld, NULL) != 0 ||
                    sigprocmask(SIG_SETMASK, &original_mask, NULL) != 0) {
                    fprintf(stderr, "cannot restore worker signal state: %s\n", strerror(errno));
                    _exit(LC_EXIT_FAILED);
                }
                return i;
            }
            int fork_error = errno;
            born_ms[i] = lc_now_ms();
            if (pid < 0) {
                /* A healthy worker need not exit to make a failed slot retry.
                 * Use the existing procd interval rather than spin on EAGAIN. */
                fork_failed = 1;
                retry_ms[i] = born_ms[i] + (uint64_t)WORKER_RESPAWN_S * 1000u;
                fprintf(stderr, "cannot fork worker %u of %u: %s\n", i + 1u, workers,
                        strerror(fork_error));
                continue;
            }
            kids[i] = pid;
        }

        if (supervisor_usr1) {
            supervisor_usr1 = 0;
            for (unsigned i = 0; i < workers; i++)
                if (kids[i] > 0)
                    (void)kill(kids[i], SIGUSR1);
        }
        if (supervisor_usr2) {
            supervisor_usr2 = 0;
            for (unsigned i = 0; i < workers; i++)
                if (kids[i] > 0)
                    (void)kill(kids[i], SIGUSR2);
        }

        int   status = 0;
        pid_t gone = waitpid(-1, &status, WNOHANG);
        if (gone < 0) {
            if (errno == EINTR)
                continue;
            if (errno != ECHILD) {
                fprintf(stderr, "cannot inspect supervisor children: %s\n", strerror(errno));
                _exit(LC_EXIT_FAILED);
            }
            unsigned live = 0;
            for (unsigned i = 0; i < workers; i++)
                live += kids[i] > 0;
            /* All forks failed: procd owns the next startup attempt. A last
             * worker's short crash may instead have a pending respawn deadline. */
            if (fork_failed || live != 0u)
                _exit(LC_EXIT_FAILED);
        }
        /* A WORKER THAT EXITED WITH A FAILURE TAKES THE GROUP WITH IT, and procd decides what comes
         * next. That is how a worker says it could not start — above all on the Hysteria2 plane,
         * where a node that does not answer at start is an exit, as it is for the reference (see
         * main). Forking it again from here would do it with no pause at all: a resolver that fails
         * at once would have this loop spinning on fork. A worker ended by a signal is a crash, and
         * is replaced. */
        if (gone > 0)
            lc_worker_event(status, LC_VERSION, (unsigned long long)(lc_now_ms() / 1000u), plane);
        if (gone > 0 && WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            fprintf(stderr, "worker (pid %d) exited with %d; stopping the others\n", (int)gone,
                    WEXITSTATUS(status));
            for (unsigned i = 0; i < workers; i++)
                if (kids[i] > 0 && kids[i] != gone)
                    (void)kill(kids[i], SIGTERM);
            _exit(WEXITSTATUS(status));
        }
        for (unsigned i = 0; gone > 0 && i < workers; i++) {
            if (kids[i] != gone)
                continue;
            kids[i] = -1;
            fprintf(stderr, "worker %u of %u (pid %d) ended%s; starting another\n", i + 1u, workers,
                    (int)gone, WIFSIGNALED(status) ? " on a signal" : "");
            now = lc_now_ms();
            retry_ms[i] = now - born_ms[i] < (uint64_t)WORKER_RESPAWN_S * 1000u
                ? now + (uint64_t)WORKER_RESPAWN_S * 1000u : 0u;
            break;
        }
        if (gone > 0)
            continue; /* Drain exits before sleeping, without blocking other slots. */

        uint64_t next_retry = UINT64_MAX;
        for (unsigned i = 0; i < workers; i++)
            if (kids[i] < 0 && retry_ms[i] < next_retry)
                next_retry = retry_ms[i];
        struct timespec delay, *timeout = NULL;
        if (next_retry != UINT64_MAX) {
            now = lc_now_ms();
            uint64_t ms = next_retry > now ? next_retry - now : 0u;
            delay.tv_sec = (time_t)(ms / 1000u);
            delay.tv_nsec = (long)((ms % 1000u) * 1000000u);
            timeout = &delay;
        }
        int wait_rc = pselect(0, NULL, NULL, NULL, timeout, &wait_mask);
        if (wait_rc < 0 && errno != EINTR) {
            fprintf(stderr, "cannot wait for supervisor events: %s\n", strerror(errno));
            _exit(LC_EXIT_FAILED);
        }
    }
}

/* THE DESCRIPTOR LIMIT AS GO LEAVES IT, which both references run under and this did not.
 *
 * Go raises the soft RLIMIT_NOFILE to one below the hard limit in the syscall package's init,
 * before main runs, in every program (GOROOT/src/syscall/rlimit.go:30-47) — so Xray and hysteria
 * start with whatever the service manager's hard limit is, 4096 by the kernel's default, where a C
 * program keeps the soft 1024. That did not matter while the session table stopped at 256; with no
 * ceiling but memory (see `sessions`), 1024 would have been the ceiling instead — a stream holds
 * two descriptors and two more while it splices, a REALITY datagram session one per address. Done
 * the same way: Max - 1, and a refusal ignored, as the reference ignores it. Before the workers are
 * forked, so each inherits it. */
static void raise_nofile(void)
{
    struct rlimit lim;
    if (getrlimit(RLIMIT_NOFILE, &lim) == 0 && lim.rlim_max > 0 && lim.rlim_cur < lim.rlim_max - 1) {
        lim.rlim_cur = lim.rlim_max - 1;
        (void)setrlimit(RLIMIT_NOFILE, &lim);
    }
}

int main(int argc, char **argv)
{
    /* Before any socket exists: a write to a peer that has gone must not end the process. */
    lc_ignore_sigpipe();
    /* exec preserves ignored dispositions and blocked signals. Establish TERM
     * before listeners/forks so service stop and PR_SET_PDEATHSIG can release
     * every worker's descriptors, even when the launcher suppressed TERM. */
    struct sigaction term_action;
    memset(&term_action, 0, sizeof term_action);
    term_action.sa_handler = SIG_DFL;
    sigemptyset(&term_action.sa_mask);
    if (sigaction(SIGTERM, &term_action, NULL) != 0) {
        fprintf(stderr, "cannot restore SIGTERM disposition: %s\n", strerror(errno));
        return LC_EXIT_FAILED;
    }
    sigset_t term_mask;
    sigemptyset(&term_mask);
    sigaddset(&term_mask, SIGTERM);
    if (sigprocmask(SIG_UNBLOCK, &term_mask, NULL) != 0) {
        fprintf(stderr, "cannot unblock SIGTERM: %s\n", strerror(errno));
        return LC_EXIT_FAILED;
    }
    raise_nofile();
    /* THE LOG NO LONGER GOES THROUGH stdio AT ALL, so there is nothing here to set a mode on.
     *
     * This used to be `setvbuf(stdout, NULL, _IOLBF, 0)`, and the reason it was is worth keeping:
     * left at the default the stream is flushed in blocks, so a run that ends by being killed —
     * which is how anything under a service manager ends — writes nothing at all, and that is
     * exactly what happened the first time this ran on a router. Three requests succeeded and the
     * log was empty.
     *
     * Line buffering answered that and stopped answering it the moment there were four workers on
     * one pipe: see note(), which now builds each line and writes it in one call. A write beats a
     * buffering mode on both counts — it cannot lag, and it cannot be interleaved. What is left on
     * stdout is `--planes` and `--version`, one line each, printed and then exited on, which flushes
     * them. */

    /* Two shapes, because the planes have nothing in common but a listener. REALITY needs a
     * fingerprint table, a public key, a short id and an account; Hysteria2 needs a password and
     * usually an obfuscation password. One positional list serving both would be six arguments that
     * mean nothing to whichever plane is not in use. */
    if (argc == 2 && strcmp(argv[1], "--planes") == 0)
        planes();

    /* WHICH BUILD THIS IS, because for a whole day of deploying to a router the answer lived in a
     * checksum and somebody's memory. Five binaries went onto one box by hand; asking it afterwards
     * what it was running meant comparing md5sums against files in a temporary directory.
     *
     * Stamped by the Makefile from `git describe`, so it names a commit and says whether the tree
     * was dirty when the binary was made — the second half being the one that matters, since a
     * binary built from uncommitted work is exactly the one nobody can reconstruct later. */
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("%s\n", LC_VERSION);
        return LC_EXIT_OK;
    }

    hy.on = argc >= 2 && strcmp(argv[1], "-H") == 0;
    on_hy_plane = hy.on;
    if (hy_setup() != 0) {
        note("no memory for the node's connection");
        return LC_EXIT_FAILED;
    }

    /* Answered rather than ignored. A build without the plane still knows what -H means, and the
     * one thing it must not do is accept it and then fail to carry anything — which is what the
     * quiet version of this looks like from the other end. */
    if (hy.on && !LC_HYSTERIA) {
        fprintf(stderr, "this build has no hysteria2 plane; rebuild with HYSTERIA=1\n");
        return LC_EXIT_CONFIG;
    }


    static uint8_t    table[MAX_TABLE];
    long              table_len = 0;
    const char       *node = NULL, *sni = NULL;
    uint16_t          node_port = 0, listen_port = 0;
    /* Filled once, below, on the REALITY plane only — the Hysteria plane holds one UDP connection
     * for the life of the run and resolves it inside lc_qconn_open. Lives in main's frame because
     * the loop does too, and every session borrows it. */
    lc_resolved       node_addr;
    uint8_t           uuid[LC_VLESS_UUID];
    lc_reality_config reality;
    int               first_option;

    memset(uuid, 0, sizeof uuid);
    memset(&reality, 0, sizeof reality);

    if (hy.on) {
        if (argc < 8)
            usage();

        node = hy.node = argv[2];
        /* A PORT OR A RANGE. `443` is one port; `20000-50000` asks the client to move across the
         * range every half minute or so — upstream's own answer, written the same way, to a path
         * that shapes UDP on whichever port it sees. What the node needs for it is a firewall
         * redirect from the range to the single port it already listens on, and no configuration.
         *
         * Measured on a live router before this existed: six seconds of complete UDP silence at a
         * time with the loop awake and ICMP over the same route at zero loss. */
        /* A hop address when the port holds a '-' or a ',' — isPortHoppingPort
         * (vendor/hysteria/app/cmd/client.go:1257-1261) — read as ParsePortUnion reads it: ranges
         * and single ports, a reversed range turned round, the whole normalized (core/portunion.h).
         * ⚠️ Until 2026-09-27 one `lo-hi` and nothing else, and a reversed one was refused. */
        {
            if (strchr(argv[3], '-') != NULL || strchr(argv[3], ',') != NULL) {
                if (lc_hop_ports_parse(argv[3], &hy.hop_ports) != 0 || hy.hop_ports.n == 0u) {
                    fprintf(stderr, "%s is not a valid port number or range\n", argv[3]);
                    return LC_EXIT_CONFIG;
                }
                node_port = hy.hop_ports.lo[0];
            } else if (lc_port(argv[3], &node_port) != 0) {
                fprintf(stderr, "%s is not a port\n", argv[3]);
                return LC_EXIT_CONFIG;
            }
        }
        hy.port = node_port;
        sni = hy.sni = argv[4];

        int rc = lc_read_secret(argv[5], hy.password, sizeof hy.password);
        if (rc != 0) {
            fprintf(stderr, "cannot read the account password: %s\n", lc_secret_why(rc));
            return LC_EXIT_CONFIG;
        }
        memset(argv[5], 'x', strlen(argv[5]));

        /* A dash means the node runs no obfuscation. Spelled out rather than left off the end,
         * because a missing argument and an empty one are too easy to confuse when the symptom of
         * getting it wrong is a node that never answers and never says why.
         *
         * Copied out and overwritten exactly as the account is, and for a reason of the same size:
         * this argument used to be a pointer into argv, so the password that gates the node's whole
         * UDP port sat in /proc/PID/cmdline — world-readable, no hidepid — for as long as the tunnel
         * ran, which is weeks. Every probe that speaks this plane already did this; the daemon,
         * where it matters most, did not. */
        if (strcmp(argv[6], "-") == 0) {
            hy.obfs[0] = '\0';
            /* The dash STAYS legible. Overwriting it left an x where the answer to "is this box
             * obfuscated" used to be, and ps is exactly where that question gets asked — an
             * unobfuscated tunnel then looked identical to one started with a secret file. Nothing
             * is hidden by masking it either: the argument is a literal password or @path, and a
             * dash is neither. */
        } else {
            rc = lc_read_secret(argv[6], hy.obfs, sizeof hy.obfs);
            if (rc != 0) {
                fprintf(stderr, "cannot read the obfuscation password: %s\n"
                                "  (write - where the node runs none)\n",
                        lc_secret_why(rc));
                return LC_EXIT_CONFIG;
            }
            memset(argv[6], 'x', strlen(argv[6]));
        }

        if (lc_port(argv[7], &listen_port) != 0) {
            fprintf(stderr, "%s is not a port to listen on\n", argv[7]);
            return LC_EXIT_CONFIG;
        }
        first_option = 8;
        goto options;
    }

    if (argc < 9)
        usage();

    table_len = lc_read_file(argv[1], table, sizeof table);
    if (table_len < 0) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return LC_EXIT_CONFIG;
    }

    /* ⚠️ AND THE TABLE IS JUDGED HERE, ONCE, BEFORE ANYTHING LISTENS.
     *
     * lc_hello_build asks lc_fpt_supported itself and returns LC_HELLO_BAD_TABLE, so a table this
     * build cannot read was already refused — per connection, on the dial path, forever. The daemon
     * started, bound the LAN port, said it was listening, and then failed every handshake; from the
     * outside that is indistinguishable from a node that is down, which is where the search goes.
     * A fingerprint table is not per-connection input. It is a file read once at startup and never
     * again, and the only honest moment to refuse it is the one where nothing has been promised yet.
     *
     * lc-probe has asked this since the requirement block was written (src/cmd/lc-probe/main.c:111);
     * the daemon, where a wrong answer costs a household its internet instead of one command, did
     * not. That asymmetry is the same shape as the alert in test/seam: the machine decided
     * correctly and the program never asked.
     *
     * Not hypothetical as of today: the GREASE-ECH record grew a candidate list and the format
     * version went 2 -> 3, so every table written before that is now one this build refuses — and
     * a router carrying one would have shown it as handshakes that never complete. */
    char why[160];
    if (lc_fpt_supported(table, (size_t)table_len, why, sizeof why) != 0) {
        fprintf(stderr, "%s: %s\n", argv[1], why);
        return LC_EXIT_CONFIG;
    }

    node = argv[2];
    if (lc_port(argv[3], &node_port) != 0) {
        fprintf(stderr, "%s is not a port\n", argv[3]);
        return LC_EXIT_CONFIG;
    }
    sni = argv[4];

    if (lc_from_hex(argv[5], reality.public_key, sizeof reality.public_key) != 0 &&
        lc_from_base64url(argv[5], reality.public_key, sizeof reality.public_key) != 0) {
        fprintf(stderr, "bad public key\n");
        return LC_EXIT_CONFIG;
    }
    size_t sid_hex = strlen(argv[6]);
    if (sid_hex % 2u != 0u || sid_hex > LC_REALITY_SHORT_ID * 2u ||
        lc_from_hex(argv[6], reality.short_id, sid_hex / 2u) != 0) {
        fprintf(stderr, "bad short id\n");
        return LC_EXIT_CONFIG;
    }
    /* The version this client gives the node: Xray's own, v26.10.31
     * (vendor/Xray-core/core/core.go:21-23), which the REALITY client writes into the
     * session ID
     * (vendor/Xray-core/transport/internet/reality/reality.go:168-170). */
    reality.version[0] = LC_REALITY_VERSION_MAJOR;
    reality.version[1] = LC_REALITY_VERSION_MINOR;
    reality.version[2] = LC_REALITY_VERSION_PATCH;

    /* The account, either written out or read from a file named with a leading @.
     *
     * A UUID on the command line is readable by every process on the machine through /proc, and it
     * is the whole credential — anyone who reads it is that subscriber until it is revoked. The file
     * form is what a router should use; the literal stays because it is what makes a one-line test
     * possible, and the argument is overwritten below either way so it does not sit in /proc for the
     * life of the process.
     *
     * Read by lc_read_secret rather than by a second copy of it. The copy that used to be here was
     * fopen into a 64-byte buffer, which TRUNCATED a longer first line and carried on — where the
     * shared one refuses — and it followed a symbolic link left in place of the file, and it looked
     * at neither the file's type nor its mode. Three behaviours, all different from the account
     * password's two lines away. */
    char uuid_text[64] = { 0 };
    int  rc = lc_read_secret(argv[7], uuid_text, sizeof uuid_text);
    if (rc != 0) {
        fprintf(stderr, "cannot read the uuid: %s\n", lc_secret_why(rc));
        return LC_EXIT_CONFIG;
    }
    if (lc_vless_uuid(uuid_text, uuid) != 0) {
        fprintf(stderr, "that is not a uuid\n");
        return LC_EXIT_CONFIG;
    }
    lc_wipe(uuid_text, sizeof uuid_text);
    /* Out of the process title. Not a substitute for the file form — anything that read it in the
     * first moments already has it — but it removes the copy that would otherwise be readable for
     * as long as the tunnel runs. */
    memset(argv[7], 'x', strlen(argv[7]));
    if (lc_port(argv[8], &listen_port) != 0) {
        fprintf(stderr, "%s is not a port to listen on\n", argv[8]);
        return LC_EXIT_CONFIG;
    }
    first_option = 9;

options:;
    /* ⚠️ THE SERVER NAME, JUDGED ONCE FOR BOTH FORMS — and it stands here rather than beside either
     * argument because the first version of this fix guarded only the REALITY branch, which is not
     * the branch the live router runs.
     *
     * Both planes take the name in argv[4] and both are wrecked by an empty one, but they are
     * wrecked differently and the Hysteria half is worse. On REALITY lc_hello_build refuses it once
     * per connection, so the tunnel listens and fails every handshake. On Hysteria2 the name goes
     * into the QUIC ClientHello, ngtcp2 refuses the write, and the daemon reports "cannot reach the
     * node: ERR_CALLBACK_FAILURE" and ARMS THE DEVICE-WIDE BACKOFF — so a config that lost one
     * option reads as a node that is down and progressively turns away new connections across the
     * whole router. Both measured on the real binary, not reasoned about.
     *
     * A config option that is simply missing must not be able to look like a network failure. */
    if (!lc_hello_sni_ok(sni)) {
        fprintf(stderr, "%s\n", lc_hello_why(LC_HELLO_BAD_SNI));
        return LC_EXIT_CONFIG;
    }
    const char *fixed_target = NULL;
    const char *flow = NULL;
    const char *udp_spec = NULL;
    unsigned    workers = 1;
    int         workers_given = 0;
    int         check_config = 0;
    /* Every token from here on is examined, and anything this does not recognise stops the process.
     *
     * The loop ran to argc - 1 and had no final else, which made two mistakes silent. A flag written
     * last — `-p` with the digest forgotten — was never looked at, and so was `-pDEADBEEF` with the
     * space left out, which is one token and not an option at all. Either way the tunnel came up,
     * carried traffic, and was NOT authenticating the node; the only difference from a correct run is
     * a line of output nobody reads twice. An option that asks for the node to be verified must not
     * be capable of being ignored. */
    for (int i = first_option; i < argc; i++) {
        const char *opt = argv[i];
        if (strcmp(opt, "--check-config") == 0) {
            check_config = 1;
            continue;
        }
        int         known = strcmp(opt, "-t") == 0 || strcmp(opt, "-f") == 0 ||
                    strcmp(opt, "-u") == 0 || strcmp(opt, "-r") == 0 || strcmp(opt, "-p") == 0 ||
                    strcmp(opt, "-j") == 0 || strcmp(opt, "-g") == 0 || strcmp(opt, "-w") == 0 ||
                    strcmp(opt, "-P") == 0 || strcmp(opt, "-c") == 0;
        if (!known) {
            fprintf(stderr, "%s is not an option this understands\n", opt);
            usage();
        }
        /* And known to THIS plane, which is not the same thing. -p and -r were accepted on the
         * REALITY plane and -f on the Hysteria2 one: parsed, stored, and never read by anything —
         * so a router configured with a certificate pin on the wrong plane started, carried traffic,
         * and authenticated nothing, with an accepted option as the evidence that it did. The
         * paragraph above says an option that asks for the node to be verified must not be capable
         * of being ignored; being ignored on the other plane is the same failure with a different
         * cause. */
        int for_hy = strcmp(opt, "-r") == 0 || strcmp(opt, "-p") == 0 || strcmp(opt, "-j") == 0 ||
                     strcmp(opt, "-g") == 0 || strcmp(opt, "-c") == 0;
        int for_reality = strcmp(opt, "-f") == 0 || strcmp(opt, "-P") == 0;
        if ((for_hy && !hy.on) || (for_reality && hy.on)) {
            fprintf(stderr, "%s means nothing on the %s plane, and doing nothing quietly is how a"
                            " node ends up unverified\n",
                    opt, hy.on ? "hysteria2" : "reality");
            return LC_EXIT_CONFIG;
        }
        if (i + 1 >= argc) {
            fprintf(stderr, "%s wants a value after it\n", opt);
            usage();
        }

        const char *val = argv[++i];
        if (strcmp(opt, "-t") == 0)
            fixed_target = val;
        else if (strcmp(opt, "-f") == 0) {
            /* REFUSED HERE, WHERE THERE IS SOMEBODY TO TELL. This protocol has one flow and the
             * absence of one (vendor/Xray-core/proxy/vless/vless.go:17-18); a third string is not a
             * flow with a different meaning. Accepting it used to start a tunnel that sent an
             * addons block naming it and ran without Vision framing — a combination no Xray client
             * produces, and one whose only symptom is a connection the node quietly refuses. */
            if (lc_vless_flow(val) < 0) {
                fprintf(stderr, "-f takes " LC_VLESS_FLOW_VISION " or nothing; \"%s\" is not a "
                                "flow this protocol has\n", val);
                return 2;
            }
            flow = val;
        }
        else if (strcmp(opt, "-u") == 0)
            udp_spec = val;
        /* `testpre`, the reference's per-account pool size — see the `spare` block. Unset, it is
         * the reference's zero, and the pool does not exist.
         *
         * The ceiling is this client's: `testpre` is a uint32 (infra/conf/vless.go:255), and every
         * pooled connection here is a whole session and a handshake on a router CPU, per worker. The
         * earlier pool measured one to four on the target router (fifteen-connection bursts, one
         * worker: 4, 8 and 16 of 60 opens served by the pool at -P 1, 2 and 4, the worst open
         * unchanged), which is the range worth offering; POOL_MAX is where it is set. */
        else if (strcmp(opt, "-P") == 0) {
            uint64_t n = 0;
            if (lc_u64(val, &n) != 0 || n > POOL_MAX) {
                fprintf(stderr, "-P wants Xray's testpre: how many connections to keep dialled ahead "
                                "of need, 0 to %u, and 0 is none\n", (unsigned)POOL_MAX);
                return LC_EXIT_CONFIG;
            }
            spare.want = (unsigned)n;
        }
        /* HOW MANY COPIES OF THIS PROCESS SHARE THE LISTENERS.
         *
         * Processes and not threads, and the reason is written in this file already: the scratch
         * buffers every connection borrows are shared on the stated grounds that "One thread, one
         * event handler at a time, and no handler ever suspends holding any of it". Threads would
         * make that sentence false and every buffer would need either a lock or a copy per thread.
         * Separate processes keep it true — nothing is shared, nothing is locked, and the kernel
         * spreads the work by hashing each connection to one member of the SO_REUSEPORT group.
         *
         * What it buys is AGGREGATE throughput, which is what a household is. Measured on the
         * target router against the stand — plain HTTP, so Vision cannot splice and every byte goes
         * through the record layer, which is the case that is CPU-bound and therefore the case this
         * is for — four downloads at once:
         *
         *     -w 1   20.5 Mbit/s     655 646 631 625 KB/s, even
         *     -w 4   35.3 Mbit/s    1323 1229 954 910 KB/s, uneven
         *
         * 1.72x, not the 4x the core count suggests, and the second column says why: the kernel
         * hashes a connection to a worker, so four connections do not land one per worker. With
         * more connections — which is what a household actually has — the spread evens out.
         *
         * It does NOT make a single download faster. That connection lives in one worker from
         * beginning to end and is exactly as fast as it was.
         *
         * ⚠️ RE-MEASURED WITH REPEATS 2026-08-27, because the first pass was one run per row and the
         * thing that actually moves this number turned out to be something else entirely. Same
         * router, live server, 20 MB burst download, hand-off recorded per connection:
         *
         *     -w 1   16.8   17.1   17.9   (no hand-off in any run)
         *     -w 4   41.1   17.5   16.7   (hand-off in the first, none in the other two)
         *
         * Five of those six are the same number, and it is the AES-128-GCM ceiling on this box. The
         * worker count moves nothing; the outlier is the run where Vision handed the stream to the
         * kernel, and that is worth 2.4x. So a table of throughput against `-w` that does not record
         * the hand-off is a table of coin flips — which is what the first attempt at this one was.
         *
         * The aggregate claim above survives the same treatment: four streams at once went 21.3 to
         * 29.1 Mbit/s on that node and 17.8 to 35.6 on another, both in the direction stated here.
         *
         * ⚠️ AND IT DOES NOT SHOW ON THE WIRE, which is the question worth asking of anything that
         * changes how many connections a client opens. Each worker dials the node itself, so the
         * node sees several at once from one address — and that is the reference's own habit rather
         * than something new: it keeps a pool of connections dialled AHEAD of need,
         * `h.preConns <- &ConnExpire{Conn: conn, Expire: time.Now().Add(time.Minute * 2)}` two
         * hundred milliseconds apart (vendor/Xray-core/proxy/vless/outbound/outbound.go, the
         * pre-connect goroutine). Several live connections from one client is what upstream looks
         * like. Each worker also builds its own hello from the same table, so the GREASE and the
         * padding are drawn per connection exactly as they are for a browser opening several.
         *
         * ⚠️ AND ON THE HYSTERIA2 PLANE IT CANNOT BE USED AGAINST A SERVER THAT KEEPS ONE SESSION PER
         * PASSWORD. Every worker dials with the same `auth`, and servers that sell a subscription as one
         * active connection are patched to close each earlier session of an authID the moment a newer
         * one registers. So the workers evict one another in turn, and what a measurement sees is a run
         * of 0x107 closes (closeErrCodeTrafficLimitReached, vendor/hysteria/core/server/server.go:24,
         * which such a patch reuses) rather than a tunnel that is merely slow. Read out of such a server
         * on 2026-09-07 after it had been taken for a path that blocks: 271 such closes belonged to
         * two processes sharing an auth, and none at all to the single service.
         *
         * Upstream hysteria has no such rule, which is why `-w` measures cleanly against the reference
         * server. One live session per subscription is a server's deliberate decision about what a
         * subscription IS, so this is a constraint to state here rather than a defect to route around.
         *
         * REALITY has no equivalent: Xray does not evict, so the measurement above is the whole
         * story on that plane.
         *
         * ⚠️ `auto` READS THE MACHINE, and it is the value a fleet should use. This first said a
         * number was enough because "a router knows its own hardware and its operator does too",
         * which is true of one router and false of a park of them: the same configuration reaches
         * a two-core box and a four-core box, and a number chosen for one is wrong on the other —
         * too few workers wastes a core, too many cost buffers to no purpose. What the kernel
         * reports online is the honest answer on every model, so it is the one the config uses.
         *
         * It counts what the kernel calls a CPU, which on this target is four hardware threads
         * across two cores, not four cores. That is the right count anyway: the workers stall on
         * memory as much as they compute, and threads sharing a core still overlap that. The
         * measurement is written above and was taken at exactly this value.
         *
         * The ceiling is eight because a worker costs its own buffers and no router this runs on
         * has more; a machine reporting more gets eight rather than a refusal, since refusing to
         * start over an abundance of cores would be absurd. */
        else if (strcmp(opt, "-w") == 0) {
            workers_given = 1;
            if (strcmp(val, "auto") == 0) {
                long n = sysconf(_SC_NPROCESSORS_ONLN);
                /* A kernel that will not say is not a failure: one worker is what this did before
                 * the option existed, and it is always correct. */
                workers = n < 1 ? 1u : (n > 8 ? 8u : (unsigned)n);
            } else {
                uint64_t n = 0;
                if (lc_u64(val, &n) != 0 || n < 1u || n > 8u) {
                    fprintf(stderr, "-w wants how many workers share the listeners: 1 to 8, or "
                                    "auto for one per CPU the kernel reports\n");
                    return LC_EXIT_CONFIG;
                }
                workers = (unsigned)n;
            }
        }
        /* MOVE THE FLOW, because a shaper acts on a flow and a flow is four numbers.
         *
         * Measured on a live router: UDP to the node goes silent for six seconds at a time while
         * ICMP over the same route runs at zero loss, and TCP to the SAME node — the phone and the
         * desktop go through it over REALITY all day — never stalls at all. Same house, same hour,
         * same address; what differs is the transport, so what is acting is something that treats
         * this UDP flow differently. A flow it has learned about can be left behind by becoming a
         * different flow, and the cheapest way to become one is a new source port.
         *
         * Off unless asked for. It rests on the node accepting that a connection may arrive from
         * somewhere new — which QUIC is built for, connections being known by their identifier
         * rather than their address — but "built for" and "does" are different claims, and the one
         * that matters here can only be settled on the node we actually have. */
        /* FIVE, NOT ONE, AND THE FLOOR IS THE REFERENCE'S.
         *
         * udphop refuses outright — `if c.Min < 5*time.Second { return HopIntervalConfig{},
         * errors.New("hop interval must be at least 5 seconds") }`
         * (vendor/hysteria/extras/transport/udphop/conn.go:117-119) — so a client asking to move
         * faster than that does not start.
         *
         * This accepted 1 to 3600, and lc_qconn_hop_on then quietly turned hopping OFF for anything
         * under five while the tunnel came up regardless. The comment there said the refusal was
         * "answered where it belongs, at the argument, which refuses with LC_EXIT_CONFIG and a line
         * naming the minimum" — and no such refusal existed anywhere in the tree. So `hop_seconds 3`
         * gave a router that started, logged one line nobody reads twice, and never moved its port:
         * the operator reads one number in the config and the wire carries another, which is the
         * exact fault the note was written to prevent. */
        /* `N` is hopInterval, `MIN-MAX` is minHopInterval and maxHopInterval — a fresh interval in
         * that span for every move (vendor/hysteria/app/cmd/client.go:127-131, :360-377,
         * vendor/hysteria/extras/transport/udphop/conn.go:165-170). No upper bound but the one an
         * interval in milliseconds needs: the reference has none. ⚠️ Until 2026-09-27 one number,
         * at most 3600 — a ceiling the reference does not have, and no span at all. */
        else if (strcmp(opt, "-j") == 0) {
            uint64_t    lo = 0, hi = 0;
            const char *dash = strchr(val, '-');
            char        first[24];
            int         bad = 0;
            if (dash != NULL) {
                size_t n = (size_t)(dash - val);
                bad = n == 0u || n >= sizeof first;
                if (!bad) {
                    memcpy(first, val, n);
                    first[n] = '\0';
                    bad = lc_u64(first, &lo) != 0 || lc_u64(dash + 1, &hi) != 0;
                }
            } else {
                bad = lc_u64(val, &lo) != 0;
                hi = lo;
            }
            if (bad || lo < HOP_MIN_SECS || hi < lo || hi > 4294967u) {
                fprintf(stderr, "-j wants seconds between moves, N or MIN-MAX, at least %u and the "
                                "minimum not over the maximum — as the reference refuses\n",
                        (unsigned)HOP_MIN_SECS);
                return LC_EXIT_CONFIG;
            }
            hy.hop_min = (unsigned)lo;
            hy.hop_max = (unsigned)hi;
        }
        /* Bytes per second, which is what this protocol counts in however its configuration is
         * written. Stating one is what makes the node send at that rate whatever the path does — and
         * stating zero is what turns that off, which is why the value is parsed rather than handed to
         * strtoull: "100mbps", the spelling hysteria's config uses, came back as 100 and "abc" as 0,
         * both without a word, and the tunnel then ran on ordinary congestion control while its log
         * said it had asked for a rate. */
        else if (strcmp(opt, "-r") == 0) {
            if (lc_u64(val, &hy.rx_rate) != 0) {
                fprintf(stderr, "%s is not a receive rate in bytes per second\n", val);
                return LC_EXIT_CONFIG;
            }
        }
        /* The node's certificate digest. Without it a completed handshake proves only that something
         * on the path can do a key exchange, which is a thing an interceptor can also do. */
        else if (strcmp(opt, "-p") == 0) {
            /* A single dash is "no pin, and I mean it", the same spelling OBFS_PASSWORD already uses
             * for the node that runs no obfuscation. It exists so that running unauthenticated is a
             * thing somebody typed rather than a thing that happens when an argument is forgotten —
             * see the refusal in main for what the reference does here. */
            if (strcmp(val, "-") == 0) {
                hy.pin_waived = 1;
            } else {
                if (lc_from_hex(val, hy.pin, sizeof hy.pin) != 0) {
                    fprintf(stderr, "the pin is not %u hex bytes\n", (unsigned)sizeof hy.pin);
                    return LC_EXIT_CONFIG;
                }
                hy.have_pin = 1;
            }
        }
        else if (strcmp(opt, "-g") == 0) {
            /* Written out as two numbers rather than accepted as a bare switch, because these are
             * what the node was configured with and a mismatch is not an error anywhere: the frames
             * still decode, they are simply the wrong size, which is the one thing this layer is
             * for. The reference's defaults are 512-1200. */
            char        sizes[64];
            snprintf(sizes, sizeof sizes, "%s", val);
            char *dash = strchr(sizes, '-');
            if (dash == NULL) {
                fprintf(stderr, "-g wants MIN-MAX, the datagram sizes the node was told to use"
                                " (the reference's own are 512-1200)\n");
                return LC_EXIT_CONFIG;
            }
            *dash = '\0';
            uint16_t lo = 0, hi = 0;
            if (lc_u16(sizes, &lo) != 0 || lc_u16(dash + 1, &hi) != 0 || lo == 0 || lo > hi) {
                fprintf(stderr, "-g wants MIN-MAX with MIN at least one and no more than MAX\n");
                return LC_EXIT_CONFIG;
            }
            /* The reference's own ceiling, geckoBufferSize, rather than its default. A node whose
             * operator set anything between 1201 and 2048 — which the reference accepts — could not
             * be configured here at all. */
            if (hi > LC_GECKO_BUFFER) {
                fprintf(stderr, "-g cannot exceed %u, which is what the node's own client accepts\n",
                        (unsigned)LC_GECKO_BUFFER);
                return LC_EXIT_CONFIG;
            }
            hy.gecko_min = lo;
            hy.gecko_max = hi;
        }
        else if (strcmp(opt, "-c") == 0) {
            /* Chrome's QUIC stack, parroted — the hello, the transport parameters, the connection
             * IDs, the first packets — which is what hysteria's client does unless its config says
             * quic.disableChromeParrot (vendor/hysteria/app/cmd/client.go:172, passed on at :470).
             * Spelled as a value so that the default can be either without the flag changing
             * meaning — and the default is on, the reference's since hysteria 2.11. */
            if (strcmp(val, "on") == 0)
                hy.plain = 0;
            else if (strcmp(val, "off") == 0)
                hy.plain = 1;
            else {
                fprintf(stderr, "-c wants on or off\n");
                return LC_EXIT_CONFIG;
            }
        }
    }

    /* GECKO WITHOUT SALAMANDER IS NOT A CONFIGURATION, AND IT WAS ACCEPTED AS ONE.
     *
     * Upstream cannot even construct the pair: WrapPacketConnGecko opens with
     *
     *     if len(opts.Password) == 0 {
     *         return nil, errors.New("gecko: password is required")
     *     }
     *     ...
     *     inner, err := WrapPacketConnSalamander(conn, opts.Password)
     *                            (vendor/hysteria/extras/obfs/gecko.go:34-52)
     *
     * so Gecko exists only ever wrapped around Salamander, and no hysteria client can emit an
     * unobfuscated Gecko frame. Ours could: `-g 512-1200` with no `-o` left lc_obfs_init with the
     * obfuscator off (src/quic/obfs.c:13-14), and every handshake datagram then went out as a
     * Gecko frame IN THE CLEAR — byte 0 a constant 0x80, byte 1 a counter incrementing by one per
     * packet, byte 2 the chunk index and count, bytes 3-4 a big-endian pad length, then the pad.
     * A five-byte structured header on a UDP port, on every connection attempt, readable without
     * decrypting anything and produced by nothing else in the world.
     *
     * It did not even work: the node XORs the frame with its PSK before parsing, so the connection
     * never came up. A configuration that cannot succeed and advertises the client while failing
     * is the worst of both, and refusing it costs one comparison. */
    if (hy.gecko_min != 0 && hy.obfs[0] == '\0') {
        fprintf(stderr, "-g needs -o: the node's own client cannot build Gecko"
                        " without Salamander\n");
        return LC_EXIT_CONFIG;
    }

    /* AN UNAUTHENTICATED NODE IS NOW A CHOICE RATHER THAN AN OMISSION.
     *
     * After the options rather than before them, which is where the first version of this went and
     * why it refused `-p -` as well: the waiver is an option, and a check that runs before parsing
     * cannot see one.
     *
     * The reference has three states and silence is not among them. Its client builds a tls.Config
     * with `InsecureSkipVerify: c.config.TLSConfig.InsecureSkipVerify`
     * (vendor/hysteria/core/client/client.go:75-82), fed from the `insecure` option, which is FALSE
     * unless somebody writes it (vendor/hysteria/app/cmd/client.go:388) — so by default a hysteria
     * client verifies the node's certificate against the system roots and refuses when it does not
     * check out. Given `pinSHA256` it installs a VerifyPeerCertificate comparing the leaf's SHA-256
     * (vendor/hysteria/app/cmd/client.go:389-401), and Go runs that IN ADDITION to the chain, not
     * instead of it. Only `insecure: true` turns
     * verification off, and it has to be asked for.
     *
     * This client cannot do the first of those: the nodes carry self-signed certificates, so a
     * chain check has nothing to check against and would refuse every one of them. What it can do
     * is the pin, which is the same evidence the reference's second mode rests on. What it must not
     * do is the thing it did — proceed with no evidence at all because an argument was left out.
     *
     * It was not silent about it: the connect line said "NOT authenticated: no pin given, so any
     * peer that completed the handshake would have been accepted". A line in a log is not a
     * decision. `-p -` is the decision, and it is spelled the way this program already spells "the
     * node runs no obfuscation". */
    if (hy.on && !hy.have_pin && !hy.pin_waived) {
        fprintf(stderr,
                "-p is required on the hysteria2 plane: without the node's certificate digest a\n"
                "completed handshake proves only that something on the path can do a key exchange,\n"
                "which is what an interceptor does. The reference client verifies the certificate\n"
                "by default and this one cannot, because the nodes are self-signed — so the pin is\n"
                "the whole of the evidence available.\n"
                "  openssl x509 -outform der | sha256sum   on the node's certificate\n"
                "Pass `-p -` to run without it deliberately.\n");
        return LC_EXIT_CONFIG;
    }

    /* ⚠️ THE WORKERS ARE FORKED HERE, AND WHICH LISTENER EXISTS BEFORE THE FORK IS THE POINT.
     *
     * UDP is made after it, one socket per worker grouped by SO_REUSEPORT: the kernel hashes each
     * datagram's addresses to one member, so a client's datagrams land consistently in one worker,
     * which is what the per-client session model needs.
     *
     * The REALITY plane's TCP listener is made BEFORE it and shared (2026-09-24). It used to be one
     * per worker as well, and hashing is the wrong rule for connections: it does not look at load.
     * Measured on the MT7621 with four workers, two downloads opened together landed in the SAME
     * worker 4 times in 20 — that worker then carried both on one core while three idled, 26-28
     * Mbit/s where two workers gave 45-48; with the AX3000T's two workers the same draw is a coin
     * toss. The reference has no such lottery: Go runs each connection's goroutine on whichever
     * processor is free. The same rule in processes is a shared listener that wakes a worker that is
     * WAITING — LC_EV_EXCLUSIVE, EPOLLEXCLUSIVE underneath: a worker busy with a download is not in
     * its wait, so the next connection goes to one that is. And the flag is what keeps a shared
     * listener from being the thundering herd the per-worker sockets were brought in to avoid: one
     * waiter is woken per connection, not all of them (test/loop/test_share.c holds both). The
     * supervisor keeps the descriptor and never polls it; a replacement worker inherits it.
     *
     * PR_SET_PDEATHSIG, because these have no supervisor of their own. procd knows one pid; if the
     * parent dies the children must not survive holding the listeners, or the next start finds the
     * ports taken by processes nobody is watching. The getppid check after it closes the race where
     * the parent died between the fork and the prctl.
     *
     * A fork that fails is not fatal: the workers that did start are a working tunnel, and refusing
     * to run at all because the fourth copy could not be made would turn a smaller router into a
     * dead one. */
    /* UNASKED, REALITY RUNS ONE WORKER PER CPU — the reference's own default (2026-09-23, the
     * maintainer's decision). Go schedules goroutines over GOMAXPROCS, which is the number of CPUs
     * unless somebody says otherwise, so Xray's handshakes spread over every core without a line of
     * config.
     * Measured on the AX3000T against it, twenty connections at once to one node: this client spends
     * 7.2 ms of processor on a connection where the reference spends 9.9, and still reached first byte
     * 30 ms later at the median (0.48 s against 0.45) — twenty handshakes queued on one core against
     * the reference's two. With two workers the median fell by 47 ms. So the default is `auto`.
     *
     * NOT ON THE HYSTERIA2 PLANE, where it stays one: every worker would dial with the same auth and
     * a server that keeps one session per password evicts all but the newest (see the note at `-w`
     * above). The reference there is ONE QUIC connection carrying everything, and one worker is that.
     *
     * An explicit -w still wins either way, which is what the stands pass.
     *
     * Processes and not threads, so a connection stays on the core that accepted it, where Go moves
     * goroutines between cores as it likes; and at most eight (DIVERGES: O1). */
    if (!workers_given && !hy.on) {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        workers = n < 1 ? 1u : (n > 8 ? 8u : (unsigned)n);
    }

    /* The Chrome this process claims, clock and draw, fixed at start as the reference's package
     * init fixes them — and before any fork, so every worker claims that one (reality/browser.c). */
    if (!check_config)
        lc_browser_anchor();

    int shared_listen_fd = -1;
    if (workers > 1 && !check_config) {
        /* REALITY's process-wide path set is required before listeners or workers
         * exist (vendor/Xray-core/transport/internet/reality/reality.go::UClient,
         * maps.Lock). Per-worker caches would change later path choices. */
        if (!hy.on && lc_spider_paths_share() != 0) {
            note("cannot initialize shared spider paths: %s", strerror(errno));
            return LC_EXIT_FAILED;
        }
        /* The shared listener — see above. Not on the Hysteria2 plane, whose workers exist only when
         * a stand asks for them by hand, and whose listeners open once its client exists. */
        if (!hy.on) {
            shared_listen_fd = lc_tproxy_listen(listen_port, fixed_target == NULL);
            if (shared_listen_fd < 0) {
                note("cannot listen on %u%s", listen_port,
                     fixed_target == NULL ? " (transparent mode needs CAP_NET_ADMIN)" : "");
                return LC_EXIT_FAILED;
            }
        }
        /* Before the fork, so every worker names a client identically — see gid_key_init. */
        gid_key_init();
        worker_no = supervise(workers, hy.on ? "hysteria" : "reality"); /* only a worker returns */
        worker_total = workers;
        note("worker %u of %u, pid %d", worker_no + 1u, workers, (int)getpid());
    }

    /* Datagrams, when asked for: a port to listen on and where they go. DNS is exactly this shape
     * and is the reason it exists — a router that tunnels every stream and resolves names outside
     * the tunnel has told the network which names it was interested in. */
    int             udp_fd = -1;
    char            udp_host[256] = { 0 };
    uint16_t        udp_port_target = 0;
    int             udp_transparent = 0;
    static endpoint udp_tag = { NULL, 1 };
#if LC_HYSTERIA
    /* Whether the shared datagram socket is currently being watched. Only this plane has a queue
     * that can fill, so only this build has the gate — and the variable with it, or -Werror rightly
     * calls it out in the build that has no use for it. See the gate below. */
    int udp_read_armed = 1;
#endif

    uint16_t udp_listen_port = 0;
    if (udp_spec != NULL) {
        char spec[320];
        snprintf(spec, sizeof spec, "%s", udp_spec);

        /* PORT alone means intercepted: every datagram keeps the destination it was addressed to.
         * PORT@HOST:PORT sends them all to one place, which is what makes a resolver testable
         * without root or firewall rules. */
        char *at = strchr(spec, '@');
        if (at != NULL) {
            *at = '\0';
            /* A port has to be written after the host — 0 says so — because this form exists to
             * name one exact destination, and a default would silently pick 53 for something that
             * is not a resolver. */
            if (lc_host_port(at + 1, udp_host, sizeof udp_host, &udp_port_target, 0) != 0) {
                note("-u wants PORT or PORT@HOST:PORT, and %s is not HOST:PORT", at + 1);
                return LC_EXIT_CONFIG;
            }
        } else {
            udp_transparent = 1;
        }

        if (lc_port(spec, &udp_listen_port) != 0) {
            note("%s is not a port to listen on", spec);
            return LC_EXIT_CONFIG;
        }
    }

    /* The fixed target, split once here rather than on every connection.
     *
     * It used to be checked here and split again in the accept loop with strrchr and atoi, on the
     * grounds that the check had already refused anything atoi would read wrongly. That was true of
     * the port and of nothing else: a bare "example.com:" passed, an IPv6 literal was cut in the
     * middle of its address, and the second copy could only ever agree with the first by accident.
     * One parse, kept. */
    char     fixed_host[256] = { 0 };
    uint16_t fixed_port = 0;
    if (fixed_target != NULL &&
        lc_host_port(fixed_target, fixed_host, sizeof fixed_host, &fixed_port, 80) != 0) {
        note("%s is not a target: HOST, HOST:PORT or [V6ADDR]:PORT", fixed_target);
        return LC_EXIT_CONFIG;
    }
    int transparent = fixed_target == NULL;

    /* Use the same credential, fingerprint and option checks as startup, but no listeners,
     * workers, DNS lookup or node connection. The service asks before changing system state. */
    if (check_config)
        return LC_EXIT_OK;

    /* The summary is asked for, not scheduled: kill -USR1 and the next turn of the loop prints it. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    (void)sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = on_usr2;
    (void)sigaction(SIGUSR2, &sa, NULL);


    lc_loop *loop = lc_loop_new(64);
    reply_loop = loop;
    if (loop == NULL) {
        note("cannot start the event loop");
        return LC_EXIT_FAILED;
    }

    /* Said at startup and not only on demand: syslog is where anyone looks after the fact, and
     * "which build was that" is a question asked about a run that has already happened. */
    note("lite-client %s", LC_VERSION);


#if LC_HYSTERIA
    /* THE READER THREAD, and the one descriptor it may touch on this side: a pipe it writes a byte
     * to when a session has gained bytes, ended or failed. Started only on the plane it serves, and
     * started before any session can exist, so that no session is ever half-registered.
     *
     * No fallback. A client whose reader cannot start is a client that would read the way the
     * measurement in CONCURRENCY.md says is wrong, while reporting that it is running — so it does
     * not run. */
    if (hy.on) {
        if (pipe(reader_wake) != 0) {
            note("cannot make the reader's wake pipe: %s", strerror(errno));
            lc_loop_free(loop);
            return LC_EXIT_FAILED;
        }
        if (lc_set_nonblocking(reader_wake[0]) != 0 || lc_set_nonblocking(reader_wake[1]) != 0 ||
            lc_reader_start(reader_wake[1]) != 0) {
            note("cannot start the reader thread: %s", strerror(errno));
            lc_loop_free(loop);
            return LC_EXIT_FAILED;
        }
        if (lc_loop_add(loop, reader_wake[0], LC_EV_READ, &reader_tag) != 0) {
            note("cannot watch the reader's wake pipe");
            lc_loop_free(loop);
            return LC_EXIT_FAILED;
        }
    }
#endif

    if (hy.on) {
        /* A HOP INTERVAL WITH NOWHERE TO HOP, SAID OUT LOUD.
         *
         * hy_connect only arms hopping when the node's port was written as a range, because that is
         * the only case in which the reference hops at all — a single port takes the else branch and
         * one socket that is never replaced (vendor/hysteria/app/cmd/client.go:285). Upstream reads
         * the interval either way and then never uses it, so REFUSING here would be inventing a rule
         * it does not have.
         *
         * What upstream does not have either is a router configuration file with an option called
         * hop_seconds in it. Set that, restart, and the service comes up saying nothing; the port
         * never moves; and the operator has every reason to believe it does. Found on a live router
         * this afternoon — `hop_seconds 20` beside `port 443`, running for weeks, hopping never once
         * armed — while looking for why that tunnel kept dropping. One line, at startup, where the
         * question gets asked. */
        if (hy.hop_min != 0 && hy.hop_ports.n == 0u)
            note("hop_seconds is set and the node's port is a single one, so nothing hops — "
                   "write the port as a range (`20000-50000`) for that, and give the node a "
                   "firewall redirect from the range to the port it listens on");

        /* THE FIRST CONNECTION IS MADE BEFORE ANYTHING LISTENS, AND WITHOUT IT THE PROCESS EXITS —
         * the reference's order and the reference's answer.
         *
         * `NewReconnectableClient` with `lazy` off, its default, connects inside the constructor
         * (vendor/hysteria/core/client/reconnect.go:25-35), and runClient answers a failure with
         * `logger.Fatal("failed to initialize client")` — exit status 1 — before a single mode is
         * registered (vendor/hysteria/app/cmd/client.go:854-869, the modes from :880). So until the
         * node has answered, nothing on the LAN side is listening, and if it does not answer the
         * process is gone.
         *
         * ⚠️ WHAT STOOD HERE listened first and, where the node did not answer, stayed up and let the
         * first request try again. That was a decision about whether the process lives, taken here
         * rather than by the maintainer; the maintainer's decision is the reference's. What keeps a router whose
         * node is briefly unreachable from losing its tunnel is procd restarting the service — see
         * `respawn` in package/files/lite-client.init.
         *
         * Stepped here with nothing else on the loop, which is all the reference's constructor
         * does: one connection attempt, waited for. */
#if LC_HYSTERIA
        if (hy_connect(loop) == 0) {
            lc_event evs[4];
            while (hy.pending != 0) {
                (void)lc_loop_wait(loop, evs, 4, lc_qconn_timeout(&hy.link->c, 100));
                hy_advance(loop);
            }
        }
        if (!hy.link->up) {
            note("failed to initialize client");
            return LC_EXIT_FAILED;
        }
#endif
    }

    /* The listeners, which the reference opens only once its client exists — see above. */
    if (udp_spec != NULL) {
        udp_fd = lc_udp_listen(udp_listen_port, udp_transparent);
        if (udp_fd < 0) {
            note("cannot listen on udp %u%s", (unsigned)udp_listen_port,
                 udp_transparent ? " (transparent needs CAP_NET_ADMIN)" : "");
            return LC_EXIT_FAILED;
        }
        if (udp_transparent)
            note("udp %u, transparent", (unsigned)udp_listen_port);
        else
            note("udp %u -> %s:%u", (unsigned)udp_listen_port, udp_host, udp_port_target);
        if (lc_loop_add(loop, udp_fd, LC_EV_READ, &udp_tag) != 0) {
            note("cannot watch the udp socket");
            return LC_EXIT_FAILED;
        }
    }
    int listen_fd =
        shared_listen_fd >= 0 ? shared_listen_fd : lc_tproxy_listen(listen_port, transparent);
    if (listen_fd < 0) {
        note("cannot listen on %u%s", listen_port,
             transparent ? " (transparent mode needs CAP_NET_ADMIN)" : "");
        return LC_EXIT_FAILED;
    }
    if (lc_loop_add(loop, listen_fd, LC_EV_READ | (shared_listen_fd >= 0 ? LC_EV_EXCLUSIVE : 0u),
                    NULL) != 0) {
        note("cannot start the event loop");
        return LC_EXIT_FAILED;
    }

    if (hy.on) {
        note("listening on %u, hysteria2 to %s:%u, sni %s", listen_port, node, node_port, sni);
    } else {
        /* AN ADDRESS IS PARSED HERE, ONCE; A NAME IS NOT ASKED FOR AT ALL UNTIL A DIAL NEEDS IT.
         *
         * That is the reference: Go parses a literal and looks nothing up, and looks a name up inside
         * every dial (net/dial.h). So a name that does not resolve yet — the WAN not up, the resolver
         * still starting — is not a reason to refuse the start, as it was until 2026-09-29, when the
         * name was looked up here once and kept: the reference starts and its dials fail, each one
         * asking again, and so does this now. */
        if (lc_resolve_literal(node, node_port, &node_addr) != 0) {
            node_name = node;
            node_name_port = node_port;
        }
        note("listening on %u, node %s:%u, sni %s%s%s", listen_port, node, node_port, sni,
               flow ? ", flow " : ", no flow", flow ? flow : "");

        /* Everything a pooled dial or a redial needs, captured once. See the `spare` block for why
         * it is captured rather than threaded through the call sites. Nothing is dialled here: the
         * pool starts with the first request, as the reference's does (pool_start). */
        spare.uuid = uuid;
        spare.flow = flow;
        spare.table = table;
        spare.table_len = (size_t)table_len;
        spare.sni = sni;
        spare.reality = &reality;
        spare.node = &node_addr;
    }

    /* What this process will tell procd when the loop ends. Zero — "carried traffic" — for every
     * ordinary way out, which is all of them but one. */
    int exit_rc = 0;

    for (;;) {
        /* A second at most, and less when the shared connection has a timer of its own. QUIC's
         * timers are not advisory: a retransmission nothing wakes up to send is a stall that ends
         * as a timeout with no error reported anywhere. */
        lc_event evs[64];
        int      n = lc_loop_wait(loop, evs, 64, gcemu_wait(hy_wait(1000)));
        gcemu_tick(lc_now_ms()); /* the model of the reference's collector — see gcemu */
        if (n < 0) {
            /* Said, and not reported as success. lc_loop_wait returns -1 only when epoll_wait itself
             * failed — EINTR comes back as zero — so this is the loop's own machinery giving way,
             * and leaving through the ordinary exit told procd the run had gone fine. The exit code
             * is what decides whether the service is restarted, and `usage` promises what each one
             * means; a process that died of a broken event loop reporting "carried traffic" is the
             * one answer that stops anything being done about it. */
            note("the event loop failed: %s", strerror(errno));
            exit_rc = LC_EXIT_FAILED;
            break;
        }


        for (int i = 0; i < n; i++) {
#if LC_HYSTERIA
            if (evs[i].data == &reader_tag) {
                /* THE READER HAS PUT SOMETHING SOMEWHERE. Which session is not said and does not
                 * need to be: the byte is a nudge, not a message, and the sessions are walked below
                 * by hy_turn anyway — what this wakeup buys is that the turn happens NOW rather than
                 * whenever something else happens to wake the loop.
                 *
                 * Drained to empty, because the pipe is level-triggered and a byte left in it would
                 * make this loop spin. More than one byte is the ordinary case: the reader writes
                 * one per fill and does not wait for anyone. */
                unsigned char sink[64];
                while (read(reader_wake[0], sink, sizeof sink) > 0) {
                }
                continue;
            }
#endif


            if (evs[i].data == NULL) {
                /* A new LAN connection. */
                lc_addr dst;
                int     lan = lc_tproxy_accept(listen_fd, &dst);
                if (lan < 0) {
                    (void)accept_exhausted(loop, listen_fd);
                    continue;
                }

                char     host[256];
                uint16_t port;
                if (fixed_target != NULL) {
                    snprintf(host, sizeof host, "%s", fixed_host);
                    port = fixed_port;
                } else {
                    snprintf(host, sizeof host, "%s", dst.host);
                    port = dst.port;
                }

                session *s = session_new();
                if (s == NULL) {
                    close(lan);
                    continue;
                }
                s->lan_fd = lan;
                /* With the pool on, a request is served from it and never dials for itself — see the
                 * `spare` block; pool_tick binds the connection at the end of this turn. */
                int started = hy.on       ? hy_start(loop, s, host, port)
                              : pool_on() ? pool_wait(s, host, port)
                                          : start_tunnel(loop, s, host, port, uuid, flow, table,
                                                         (size_t)table_len, sni, &reality,
                                                         &node_addr);
                if (started != 0)
                    /* Whatever failed has already said so — start_tunnel names the reason, hy_start
                     * names its own — except the one case that is a deliberate refusal with a
                     * counter of its own (UDP/443 without a flow that allows it). */
                    session_close(loop, s);
                continue;
            }

            endpoint *ep = evs[i].data;
            if (ep == NULL)
                continue;

            /* The shared QUIC connection. Nothing is done here: every session on it is served once
             * the whole batch has been read, so that a datagram carrying bytes for three of them
             * costs one turn rather than three. */
            if (ep == &hy_tag)
                continue;

            /* A datagram. Its session is found by who sent it rather than by which descriptor woke
             * us, because every client shares the one socket. */
            if (ep->s == NULL) {
#if LC_HYSTERIA
                /* NOT READ WHILE THERE IS NOWHERE TO PUT IT, which is what the reference does and
                 * what this used to get wrong by reasoning instead of reading.
                 *
                 * hy_send_datagram still says "a datagram the connection cannot take right now is a
                 * datagram dropped, which is what UDP is" — true of the wire, and not what the
                 * reference client does. quic-go's datagram queue holds the same thirty-two frames
                 * this one does (maxDatagramSendQueueLen, vendor/quic-go/datagram_queue.go:13) and
                 * says of the limit: "Once that limit is reached, Add blocks until the queue size
                 * has reduced" (:44-47). It blocks the goroutine reading that session's socket, so
                 * the burst waits in the kernel's receive buffer rather than being thrown away.
                 *
                 * This loop cannot block — one thread carries every session — but the effect is had
                 * by stopping the read, and stopping it costs nothing that blocking would not: the
                 * queue is per CONNECTION, so while it is full no session could send anyway. The
                 * socket goes back on watch after the turn below, once flush has drained it.
                 *
                 * Measured through a real node with an echo server behind it, 1200-byte datagrams:
                 * 200/s lost nothing, 400/s 1%, 600/s 2%, 900/s 9%, and flat out 95% — the losses
                 * being ours, logged by hy_send_datagram. A thirty-two frame queue absorbs 38 ms of
                 * a 900/s stream; the receive buffer absorbs a thousand times that. */
                /* ROOM FOR THE WHOLE DATAGRAM, not for one slot, and the first version of this gate
                 * got that wrong in a way the measurement caught: it asked whether the queue was
                 * FULL, while a datagram that does not fit one frame is queued as several. A 1200
                 * byte packet — the ordinary size of what a phone sends — takes two, so at
                 * dq_count 31 the gate let the read through and lc_qconn_udp_send then refused for
                 * want of the second slot, dropping exactly where it dropped before. Both builds
                 * logged the same `dropped a 1200-byte datagram` line, which is what said so.
                 *
                 * LC_QUDP_FRAGS is the most any one datagram can need, so keeping that many slots
                 * free means anything read can always be queued. It costs the last eighth of the
                 * queue as a landing space, which is the point of it. */
                if (on_hy_plane && hy_udp_full()) {
                    if (udp_read_armed && lc_loop_mod(loop, udp_fd, 0u, &udp_tag) == 0)
                        udp_read_armed = 0;
                    continue;
                }
#endif
                uint8_t                 buf[XUDP_READ_SIZE];
                struct sockaddr_storage from;
                socklen_t               from_len = sizeof from;
                lc_addr                 dst;
                size_t                  read_cap = hy.on ? UDP_MAX_DATAGRAM : XUDP_READ_SIZE;
                long                    got = lc_udp_recv(udp_fd, buf, read_cap, &from,
                                                          &from_len, &dst);
                if (got < 0)
                    continue;
                /* An empty datagram never reaches a session on the REALITY plane: the hub drops it
                 * before its callback, `if buffer.IsEmpty() { buffer.Release(); continue }`
                 * (vendor/Xray-core/transport/internet/udp/hub.go:122-125) — no session made, none
                 * refreshed, nothing dialled. ⚠️ Until 2026-09-27 an empty one from a new client made
                 * a session and dialled the node, and one from a known client kept its session alive.
                 *
                 * And one too long for xudp is NOT dropped here any more: the hub hands the reference
                 * everything that is not empty, the session is found or made and refreshed, and only
                 * its writer drops the datagram — see the branches below, and XUDP_MAX_DATAGRAM. */
                if (!hy.on && got == 0)
                    continue;

                /* Intercepted datagrams carry their own destination; configured ones use the one
                 * given on the command line. Keyed by both, because one client talking to two
                 * resolvers is two sessions. */
                const char *want_host = udp_transparent ? dst.host : udp_host;
                uint16_t    want_port = udp_transparent ? dst.port : udp_port_target;
                if (udp_transparent && want_host[0] == '\0') {
                    stats.udp_no_dst++;
                    continue;
                }

                session *s = udp_session_for(&from, from_len, want_host, want_port);
                if (s != NULL) {
                    s->idle_deadline = lc_now_ms() + UDP_IDLE_MS;
                    udp_seen(s); /* getConnection finding it */
                    /* The address this datagram is for, remembered on the session so that a reply
                     * naming it can be answered as it. New destinations join the existing stream
                     * rather than opening one of their own — that IS the change. */
                    struct udp_dest *ud = dest_for(s, want_host, want_port);
                    if (ud == NULL) {
                        stats.udp_unroutable++;
                        continue;
                    }
                    if (udp_transparent && ud->reply_fd < 0) {
                        ud->reply_fd = lc_udp_reply_socket(&dst);
                        if (ud->reply_fd < 0) {
                            stats.udp_unroutable++;
                            continue;
                        }
                    }
                    if (s->hy_h != 0) {
                        /* Straight out. There is no queue on this plane and nothing to re-arm: the
                         * session's socket is the listener, which the loop already watches. */
                        (void)hy_send_datagram(s, ud->host, ud->port, buf, (size_t)got);
                    } else if (got == 0 || (size_t)got > udp_max_datagram(s)) {
                        /* Too long for xudp: the session was refreshed above, as the reference's
                         * getConnection refreshes it, and the datagram goes where its PacketWriter
                         * sends it — nowhere (vendor/Xray-core/common/xudp/xudp.go:99-102). */
                        /* ⚠️ AND AN EMPTY ONE IS DROPPED TOO, WHICH IS WHERE THE REFERENCE DROPS IT.
                         *
                         * A zero-length UDP datagram is a datagram — recvfrom returning 0 is not the
                         * end of anything, the way it would be on a stream — and a LAN client may
                         * send one. lc_xudp_wrap refuses to frame it, matching `if length == 0 ||
                         * length+666 > buf.Size { continue }` 
                         * (vendor/Xray-core/common/xudp/xudp.go:99-102), and said in its own
                         * comment that the caller already drops.
                         * The caller did not: a refusal came back as -1 from the datagram writer, which
                         * this branch read as fatal and answered with session_close. One empty packet
                         * from any device on the LAN took down every destination that client's xudp
                         * session was carrying — and the pending path did the same on flush.
                         *
                         * The check goes HERE rather than in the writer because the reference's
                         * is here: in the sender's own loop, before framing, where `continue` costs
                         * nothing and cannot be mistaken for an error. Found by the vendor sieve
                         * (VENDOR.md acceptance), which is the one finding of ~85 candidates that
                         * survived reading the files. */
                        stats.udp_dropped++;
                    } else if (s->st == ST_OPEN) {
                        /* INTO THE INBOUND'S PIPE, AND FROM THERE AS FAST AS THE WRITER TAKES IT.
                         *
                         * A full queue towards the node used to drop the datagram here — the right
                         * outcome for the wrong reason. The reference drops at its inbound pipe, a
                         * 16 KB pipe with DiscardOverflow (vendor/Xray-core/app/proxyman/inbound/
                         * worker.go:289), and only there: while the outbound is busy writing, the
                         * datagrams wait in that pipe and go out behind it, and one is lost only
                         * when the pipe itself is full (vendor/Xray-core/transport/pipe/impl.go:
                         * 156-160). A busy socket and a full pipe are different conditions, and
                         * dropping on the first threw away datagrams the reference would have
                         * carried a moment later.
                         *
                         * Still dropped rather than ended when it does not fit — a lost packet, not a
                         * lost connection, which is what this branch was first written to stop.
                         * pend_put is that pipe; udp_pump is the writer. */
                        pend_put(s, ud->host, ud->port, buf, (size_t)got);
                        if (udp_pump(s) != 0 || session_rearm(loop, s) != 0)
                            session_close(loop, s);
                    } else {
                        /* Still being built: into the same pipe, in arrival order. */
                        pend_put(s, ud->host, ud->port, buf, (size_t)got);
                    }
                    continue;
                }

                s = session_new();
                if (s == NULL)
                    continue;
                s->is_udp = 1;
                /* Command 0x02 or xudp, by this first datagram — `request.Command == UDP && (Flow ==
                 * XRV || (cone && Port != 53 && Port != 443))` goes to Mux
                 * (vendor/Xray-core/proxy/vless/outbound/outbound.go:303), cone being the default
                 * (vendor/Xray-core/core/xray.go:195-196). ⚠️ UNTIL 2026-09-27 always xudp, so a
                 * client without Vision sent DNS and QUIC in a frame the reference does not use. */
                s->plain_udp = !hy.on && lc_vless_flow(flow) != 1 &&
                               (want_port == 53u || want_port == 443u);
                /* Not transparent: `originalDest` is not valid, so `b.UDP` stays nil
                 * (vendor/Xray-core/app/proxyman/inbound/worker.go:314-323). ⚠️ UNTIL 2026-09-27 the
                 * configured-destination mode framed its datagrams as the transparent one does, with a
                 * global id and an address on every frame. */
                s->udp_unaddressed = !udp_transparent;
                s->lan_fd = udp_fd;
                s->peer = from;
                s->peer_len = from_len;
                client_global_id(&from, from_len, s->global_id);
                s->idle_deadline = lc_now_ms() + UDP_IDLE_MS;
                udp_seen(s);
                /* The checker starts with the first session, and its first pass runs at once — on this
                 * turn's sweep. Starting a running one does nothing (task.Periodic.Start). */
                if (!hy.on && !udp_checker.running) {
                    udp_checker.running = 1;
                    udp_checker.next = lc_now_ms();
                }
                /* The table, and the first address in it. Allocated here rather than in
                 * session_new because only a datagram session has one — a TCP session would carry
                 * it unused, and this structure is already the largest per-connection allocation
                 * this program makes. */
                s->pend_q = calloc(1, sizeof *s->pend_q);
                /* One slot on the Hysteria2 plane, where a session IS a pair — see
                 * udp_session_for — and four to start with on REALITY, where one session
                 * carries every address the client talks to, doubling as it talks to more (see
                 * struct udp_dest). */
                s->dest_cap = hy.on ? 1u : 4u;
                s->dests = calloc(s->dest_cap, sizeof *s->dests);
                if (s->dests == NULL || s->pend_q == NULL) {
                    session_close(loop, s);
                    continue;
                }
                struct udp_dest *ud0 = dest_for(s, want_host, want_port);
                if (ud0 == NULL) {
                    s->own_fail = 1;
                    session_close(loop, s);
                    continue;
                }
                /* One too long for xudp is refused by pend_put — after the session is made and with the
                 * node still dialled below, as the reference makes the connection and its writer then
                 * drops the datagram (vendor/Xray-core/common/xudp/xudp.go:99-102). */
                pend_put(s, ud0->host, ud0->port, buf, (size_t)got);
                if (udp_transparent) {
                    ud0->reply_fd = lc_udp_reply_socket(&dst);
                    if (ud0->reply_fd < 0) {
                        session_close(loop, s);
                        continue;
                    }
                }
                /* The pool serves a datagram session the way it serves a stream: the first datagram
                 * waits in pend_q with the rest, and goes out when a pooled connection is bound. */
                int opened = hy.on      ? hy_start(loop, s, want_host, want_port)
                             : pool_on() ? pool_wait(s, want_host, want_port)
                                   /* THE FLOW, WHICH THIS PASSED AS NULL. It was built on the rule
                                    * that datagrams carry none — true while they went as command
                                    * 0x02, and false now that they go as Mux: the reference rewrites
                                    * Command, Address and Port and leaves requestAddons alone, so the
                                    * flow is still in them. A live Xray refuses the other way round:
                                    * "account ... is rejected since the client flow is empty". */
                                   : start_tunnel(loop, s, want_host, want_port, uuid, flow, table,
                                                  (size_t)table_len, sni, &reality, &node_addr);
                if (opened != 0)
                    session_close(loop, s);
                continue;
            }
            session *s = ep->s;
            /* The other half of this session may already have ended it earlier in this same batch.
             * The memory is still here — that is what the deferred reap is for — but the connection
             * is gone, and acting on it would work on closed descriptors. */
            if (s->closing) {
                if (ep->is_lan == 0 && s->close_by != 0)
                    session_close(loop, s);
                continue;
            }
            if (ep->is_lan == 2) {
                if (spider_worker_ready(s) != 0 || session_rearm(loop, s) != 0)
                    session_close(loop, s);
                continue;
            }
            int lan_side = ep->is_lan;
            int fd = lan_side ? s->lan_fd : s->up_fd;

            /* A writer handled earlier in this batch may have parked this raw
             * reader. DEL does not retract events already returned by epoll. */
            if (!lan_side && s->raw_poll_paused)
                continue;

            /* A datagram session is on the loop from the client's side only while a reply waits for
             * room in the client's socket — see reply_wait. */
            if (s->is_udp && lan_side) {
                if (udp_reply_ready(loop, s) != 0 || session_done(s) || session_rearm(loop, s) != 0)
                    session_close(loop, s);
                continue;
            }

            /* An error AND something to read is not a contradiction: bytes that arrived before the
             * connection broke are still in the kernel's buffer, and epoll reports both at once. A
             * peer that answers and then resets — which is what an abrupt close looks like — is
             * exactly that shape, and taking the error first threw its answer away.
             *
             * So when there is something to read, the error is not acted on here. read() reports
             * the two in the right order by itself: the buffered bytes first, then zero or the
             * failure, both of which the paths below already end the session on. */
            if ((evs[i].events & LC_EV_ERROR) && !lc_ev_should_read(evs[i].events)) {
                /* A spider's EOF belongs to its sole Do consumer. Closing the session here used to
                 * stop and join that consumer before it could process DATA|END_STREAM already fed
                 * in the preceding event; closeafter then lost most harvested paths. */
                if (!lan_side && s->st == ST_SPIDER) {
                    if (spider_lost(s) != 0 || session_rearm(loop, s) != 0)
                        session_close(loop, s);
                    continue;
                }
                /* ⚠️ A POOLED CONNECTION THAT BREAKS WHILE IT WAITS IS NOT A NODE THAT CANNOT BE
                 * REACHED — the node plainly answered, it shook hands with us. It stays in the pool,
                 * as the reference's does, and is noticed by whichever request takes it. */
                if (!lan_side && s->st == ST_SPARE) {
                    spare_died(loop, s);
                    continue;
                }
                /* The client's side, which is on the loop only once the tunnel is open (and on the
                 * Hysteria2 plane, where it is all a session owns): its copy fails and the session
                 * ends. */
                if (lan_side || s->hy_h != 0 || s->st == ST_OPEN) {
                    session_close(loop, s);
                    continue;
                }
                /* The node's side of an attempt: a refused connect, an unreachable network, a node
                 * that reset the connection with the handshake in the air. What the kernel recorded
                 * is what is said, not a guess from the state — "refused" was once printed for every
                 * one of these, and a dropped SYN sent a day of diagnosis at a node that was
                 * answering perfectly. */
                int err = lc_socket_error(s->up_fd);
                if (s->st == ST_CONNECTING)
                    stats.dial_failed++;
                note("cannot reach the node while %s: %s",
                     s->st == ST_CONNECTING ? "connecting" : "shaking hands",
                     err != 0 ? strerror(err) : "the connection ended");
                if (dial_failed(loop, s) != 0 || session_rearm(loop, s) != 0)
                    session_close(loop, s);
                continue;
            }

            /* Still being built, and on the Hysteria2 plane that is the node's business rather than
             * this loop's: the answer comes back on the shared connection and hy_pump acts on it.
             * Nothing to do here but wait. */
            if (s->st != ST_OPEN && s->hy_h != 0)
                continue;

            /* The tunnel is still being built — or, in ST_SPIDER, has been answered by a stranger and
             * is fetching what it was shown. Every way an attempt fails ends in dial_failed below:
             * the reference's Dial returns an error for all of them and its retry takes them all. */
            if (s->st != ST_OPEN) {
                int failed = 0;

                if (s->st == ST_CONNECTING && s->dial != NULL) {
                    /* A dial to a name: its lookup or one of its connects has an answer. */
                    failed = dial_turn(loop, s) < 0;
                } else if (s->st == ST_CONNECTING) {
                    int err = lc_socket_error(s->up_fd);
                    if (err != 0) {
                        stats.dial_failed++;
                        note("cannot reach the node: %s", strerror(err));
                        failed = 1;
                    } else {
                        /* Connected: the connect's clock stops, and the handshake has none — see
                         * CONNECT_ATTEMPT_MS. */
                        s->st = ST_HANDSHAKE;
                        s->deadline = 0;
                        failed = advance_handshake(loop, s) != 0;
                    }
                } else if (s->st == ST_SPIDER) {
                    failed = spider_socket_event(s, evs[i].events) != 0;
                } else if (evs[i].events & LC_EV_WRITE) {
                    failed = q_flush(&s->to_up, s->up_fd) != 0;
                    if (!failed)
                        failed = ku_settle(s) != 0;
                    if (!failed && q_pending(&s->to_up) == 0 && s->st == ST_HANDSHAKE)
                        failed = advance_handshake(loop, s) != 0;
                } else if (evs[i].events & LC_EV_READ) {
                    failed = s->st == ST_SPARE ? spare_read(s) != 0
                                              : (handshake_read(s) != 0 ||
                                                 advance_handshake(loop, s) != 0);
                }

                /* A pooled connection that fails while it waits stays in the pool — see spare_died.
                 * One that fails while it is still being dialled does not reach ST_SPARE, and
                 * dial_failed hands it back to the pool to be dialled again. */
                if (failed && s->st == ST_SPARE) {
                    spare_died(loop, s);
                    continue;
                }
                if (failed && (s->st == ST_CONNECTING || s->st == ST_HANDSHAKE) &&
                    dial_failed(loop, s) == 0) {
                    if (session_rearm(loop, s) != 0)
                        session_close(loop, s);
                    continue;
                }
                if (failed || session_rearm(loop, s) != 0) {
                    session_close(loop, s);
                    continue;
                }
                if (s->st == ST_OPEN)
                    note_opened(s);
                continue;
            }

            int dead = 0;

            /* Writing comes first: it is what frees the room that reading needs. */
            if (evs[i].events & LC_EV_WRITE) {
                queue *q = lan_side ? &s->to_lan : &s->to_up;
                if (q_flush(q, fd) != 0)
                    dead = 1;
                /* A KeyUpdate's answer first, if one was waiting for this room: it was owed before
                 * anything the pumps below would seal. See node_key_update. */
                else if (!lan_side && ku_settle(s) != 0)
                    dead = 1;
                /* And a write that stopped between two buffers for want of room carries on now that
                 * there is some — the goroutine that was blocked in Write returning. */
                else if (!lan_side && s->hy_h == 0 && s->up_n > 0u &&
                         (s->is_udp ? udp_pump(s) : stream_pump(s)) != 0)
                    dead = 1;

                /* AND THE RECORD THAT WAS WAITING FOR EXACTLY THIS ROOM. Since the node's side is
                 * read a bufferful at a time, a read can leave whole records in hand that there was
                 * nowhere to put; the client draining is what makes somewhere, and nothing else
                 * would come back for them — the node may have nothing more to send, so no read
                 * event is owed. See records_ready. */
                if (!dead && lan_side && s->hy_h == 0 && s->st == ST_OPEN && !s->direct_in &&
                    s->rx_len > 0u && records_ready(s) != 0)
                    dead = 1;
            }

            /* The guarantee that used to be checked here — an armed read on the Hysteria2 plane
             * always having room for a whole one — belongs to the reader thread now, which asks the
             * queue for its room under the stage's lock every time and stops when there is none.
             * Nothing on that plane is armed for reading in this loop, so there is nothing to
             * check. */

            /* The request is still waiting for the client's first bytes, and this is them — or the
             * client leaving without any, which ends the session. See request_write. */
            if (!dead && lan_side && (evs[i].events & LC_EV_READ) && s->request_due) {
                if (request_read(s) != 0)
                    dead = 1;
            } else if (!dead && lan_side && (evs[i].events & LC_EV_READ) && s->hy_h == 0 &&
                       rv_current(s) > 1u) {
                /* The reference reader past its first form: see stream_take. */
                int t = stream_take(s);
                if (t < 0) {
                    dead = 1;
                } else if (t == STREAM_EOF) {
                    s->lan_eof = 1;
                }
            } else if (!dead && lan_side && (evs[i].events & LC_EV_READ)) {
                uint8_t buf[READ_CHUNK];

                /* ONE COPY, NOT TWO, ON THE PLANE THAT DOES NOT NEED THE BYTES IN HAND.
                 *
                 * The REALITY plane reads into `buf` because push_up_reshaped has to look at the
                 * bytes — it cuts the buffer at the last record start and seals each half — so they
                 * must sit somewhere this frame can address. The Hysteria2 plane does nothing to
                 * them: they are queued exactly as they arrived and handed to the QUIC stream by
                 * hy_pump. Reading into `buf` and then calling q_push there was a memcpy of every
                 * uplink byte for no reader, on a path that carries 13.5 % of the traffic of a live
                 * box — so that plane now reads into the queue's own free space, which is what
                 * q_push would have copied it to. This is the same move copy_direct already makes on
                 * the downlink, for the same reason and with the same shape.
                 *
                 * `q_room` above has already reset a fully drained queue, so `len` is the offset it
                 * will still be when the read lands: nothing between the two touches it. */
                /* ⚠️ AND THIS IS THE REALITY PLANE'S READ ONLY. On Hysteria2 the client's descriptor
                 * is read by the reader thread (net/reader.h) and is never armed for reading here,
                 * so nothing on that plane reaches this branch. The rounds that used to stand here —
                 * four bufferfuls per event, io.Copy's buffer in shape if not in mechanism — are
                 * gone with it: they were a single thread's imitation of a goroutine, and the
                 * goroutine is now real. What the measurement said about them is in CONCURRENCY.md. */
                for (;;) {
                    uint8_t *into = buf;
                    ssize_t         got = stream_read_first(s, into);
                    lc_read_outcome r = lc_read_classify((long)got, errno);
                    if (r == LC_READ_DATA) {
                        {
                            /* ReadBuffer filled the whole buffer, so the reader offers two next time:
                             * `if b.IsFull() { r.alloc.Adjust(1) }` — see stream_take. */
                            if (got == (ssize_t)READ_CHUNK)
                                rv_adjust(s, 1u);
                            /* The copy's onData, before the write, as on the other read form in
                             * stream_take: `buf.UpdateActivity(timer)` runs for every buffer the
                             * reader returns (vendor/Xray-core/proxy/vless/outbound/outbound.go:357,
                             * vendor/Xray-core/common/buf/copy.go:27-31, :91-95).
                             *
                             * ⚠️ MISSING HERE UNTIL 2026-09-27: only the multi-buffer form refreshed the
                             * timer, so a client that only ever sent less than a buffer at a time —
                             * typing, pings, a slow upload — was closed at the idle limit while
                             * Xray kept it. */
                            act_update(s);
                            if (push_up_reshaped(s, buf, (size_t)got) != 0 ||
                                q_flush(&s->to_up, s->up_fd) != 0) {
                                /* SAID, WHERE IT USED TO BE SILENT. This is the one teardown of an
                                 * established session that carried no line at all: a working, authenticated
                                 * connection went away mid-transfer and the log's account of it was the
                                 * absence of any further mention. The room the read needed is reserved
                                 * before the read is armed (UP_WORST_PER_READ), so reaching here at all
                                 * means either the framing outgrew that reserve — which the assertions
                                 * beside it exist to prevent — or the socket towards the node failed. */
                                note("%s:%u ended while sending: the node's socket or the uplink queue"
                                     " refused what the client sent",
                                     s->target_host, s->target_port);
                                dead = 1;
                            }
                        }
                    } else if (r == LC_READ_EOF) {
                        /* THE CLIENT HAS FINISHED, SO THE SESSION IS FINISHED — which is what the
                         * reference does and what this used to invent its way around.
                         *
                         * hysteria's transparent proxy is two io.Copy goroutines and one channel:
                         * `closeErr = <-copyErrChan` returns as soon as EITHER direction ends, and the
                         * deferred closes then take both
                         * (vendor/hysteria/app/internal/redirect/tcp_linux.go:69-79). A client
                         * half-close ends the first copy, so the pair goes. There is no timer anywhere
                         * in it, no waiting for a late answer, and nothing counted.
                         *
                         * What stood here instead was a five-second wait for an answer after the
                         * half-close, and — the part that did real damage — those waits were recorded as
                         * evidence that the NODE was broken. Measured on a router: every one of them was
                         * an ordinary keep-alive that had been answered and gone quiet, and three inside
                         * thirty seconds threw away the QUIC connection carrying every other session,
                         * about twenty times an hour. An invention that manufactured the fault it was
                         * written to detect.
                         *
                         * ⚠️ THE STORY ABOVE IS THE HYSTERIA2 PLANE'S, AND THIS BRANCH NO LONGER
                         * RUNS THERE: its client descriptor is read by the reader thread, which
                         * marks the end, and hy_send_up closes the session. What reaches this line
                         * is REALITY, where the client's end only ends the uplink copy: the
                         * reference passes nothing on and moves its timer — see the end of this
                         * turn. */
                        s->lan_eof = 1;
                    } else if (lc_ev_finished(evs[i].events, r)) {
                        /* Either the descriptor is finished, or there is nothing to read and the event
                         * carried an error — which is the same thing, arriving one step later. */
                        dead = 1;
                    }
                    break;
                }
            }

            /* Raw pass-through, once the node has said the rest is not framed: no record layer, no
             * AEAD, and with splice not even a copy into this process.
             *
             * The queue is drained first. It still holds whatever came in the same record as the
             * announcement, and starting to splice before that has gone out would deliver the
             * stream out of order. */
            if (!dead && s->direct_in) {
                if (direct_pump(s, !lan_side && (evs[i].events & LC_EV_READ) != 0) != 0)
                    dead = 1;
            } else if (!dead && !lan_side && (evs[i].events & LC_EV_READ)) {
                /* One read of as much as the buffer holds — node_read_ahead — then whatever whole
                 * records that produced. What the records in it turn into is records_ready's
                 * business, including an xudp End, which takes the same door a closed socket takes
                 * two branches down rather than the failure door — see LC_XUDP_ENDED. */
                stats.reads_up++;
                /* Ahead only where there are threads to open what it brings: on a single
                 * processor a larger read changes nothing but the number of calls, and the reads
                 * stay the reference's. A session reading ahead goes on doing so — node_fill
                 * would read past the bytes `rin` has not been given. */
                int got = recopen != NULL || s->rin_ahead > 0u ? node_read_ahead(s)
                                                              : node_fill(s, node_want(s));
                if (got >= 0) {
                    if (records_ready(s) != 0)
                        dead = 1;
                } else if (got == -2) {
                    /* Before the VLESS response has arrived, the end of the stream is a failure and
                     * not a half-close: the reference reads the response header first, and
                     * DecodeResponseHeader's error on an empty stream ends the whole Process
                     * (vendor/Xray-core/proxy/vless/outbound/outbound.go:372-375) — both sides go.
                     * Only after it does the downlink's end merely move the timer to UPLINK_ONLY_MS
                     * while the uplink goes on.
                     * With the request waiting on the client this was a node that had closed on a
                     * session still holding its LAN side open for an answer that could never come. */
                    if (!s->vless_header_seen)
                        dead = 1;
                    else
                        s->up_eof = 1;
                } else {
                    dead = 1;
                }
            }

            /* THE END OF EACH COPY, AND WHAT IT MOVES — which on the REALITY plane is the timer and
             * nothing on either socket.
             *
             * The uplink copy ends when the client has finished and everything it said has been
             * written: `defer timer.SetTimeout(DownlinkOnly)`. The downlink copy ends when the node has
             * finished and everything it sent has reached the client: `defer
             * timer.SetTimeout(UplinkOnly)` (vendor/Xray-core/proxy/vless/outbound/outbound.go:310,
             * :370). Neither shuts a direction of anything — `task.Close(clientWriter)` is a no-op
             * on dokodemo's writer, which has no Close — so the node hears nothing until the
             * connection ends and the client hears its FIN only then. session_done ends it when both
             * copies have; the timer, when it fires first.
             *
             * A datagram session's downlink ends with the stream, whatever partial frame is left: the
             * reader returns EOF and the frame is lost with it. Its uplink never ends on its own — the
             * inbound's pipe does not close until the checker or the timer ends the session.
             *
             * The Hysteria2 plane ends a stream in hy_pump, the moment either side does; nothing here
             * applies to it. */
            if (!dead && s->hy_h == 0) {
                if (s->lan_eof && !s->req_done && q_pending(&s->to_up) == 0 && s->up_n == 0u) {
                    s->req_done = 1;
                    act_set(s, DOWNLINK_ONLY_MS);
                }
                if (s->up_eof && !s->resp_done &&
                    (s->is_udp || (q_pending(&s->to_lan) == 0 && s->in_pipe == 0 &&
                                   (!s->direct_in || s->rx_len == 0u)))) {
                    s->resp_done = 1;
                    act_set(s, UPLINK_ONLY_MS);
                }
            }

            if (dead || session_done(s) || session_rearm(loop, s) != 0) {
                session_close(loop, s);
                continue;
            }
        }

        if (want_reset) {
            want_reset = 0;
            memset(&stats, 0, sizeof stats);
#if LC_HYSTERIA
            /* And the write loop's own counters, which the summary prints beside these and which
             * live on the connection rather than in `stats`. Left alone, every other line of the
             * summary counted from the reset and this one from the start of the connection, so the
             * two could not be read together — which is what a reset before a measurement is for.
             * Only this thread touches them (flush, in quic/conn.c). */
            hy.link->c.tx_stop_paced = hy.link->c.tx_stop_dry = hy.link->c.tx_stop_blocked = 0;
            hy.link->c.tx_stop_yield = hy.link->c.tx_packets = 0;
#endif
            note("counters reset");
        }
        if (want_stats) {
            report_stats();
#if LC_HYSTERIA
            /* WHY THE WRITE LOOP STOPPED. What the three numbers mean, and which of them is the
             * reference's behaviour and which is ours, is at their declaration in quic/conn.h —
             * said once there because it has already been rewritten twice in a day and four copies
             * of it would have disagreed by the second rewrite.
             *
             * Printed here rather than inside report_stats for the dull reason that the Hysteria2
             * state is declared below that function, and a summary that cannot see the connection
             * cannot report on it. */
            if (on_hy_plane) {
                uint64_t stops =
                    hy.link->c.tx_stop_paced + hy.link->c.tx_stop_dry + hy.link->c.tx_stop_blocked +
                    hy.link->c.tx_stop_yield;

                /* ⚠️ ONE LINE, AND THE SECOND ONE IS FOLDED INTO IT ONLY WHEN IT HAS NEWS. This
                 * summary is not printed once: /usr/sbin/lc-stats on the routers pokes it with
                 * SIGUSR1 every fifteen minutes, and syslog is a 128 KB ring. That script's own
                 * comment records the interval being raised from five minutes to fifteen because
                 * seven lines of this block were pushing everything else out — 644 of 1112 lines on
                 * 19 August. The block is thirteen lines now, two of them added on 19 September, and
                 * the ring was back to 688 of 1097 within a day: about fourteen hours of history,
                 * which is not enough to tell "it started last night" from "it has always been so".
                 *
                 * So the stale-generation counter, which counts a RACE and is expected to read zero
                 * for months, no longer spends a line saying zero. It appears when it is not zero,
                 * which is the only time anyone needs it. */
                char stale[80];

                stale[0] = '\0';
                if (stats.up_stale_gen != 0)
                    snprintf(stale, sizeof stale, " | %llu offered to a replaced connection",
                             (unsigned long long)stats.up_stale_gen);

                /* And how many of the node's packets were opened ahead on the other cores
                 * (quic/rxopen.h), on the same line for the reason above. */
                unsigned long long ahead = 0, missed = 0;
                lc_qcrypto_hint_counts(&ahead, &missed);
                note("write loop: %llu passes, %llu ended by the pace, %llu with nothing left to "
                     "write, %llu with the socket full, %llu yielded to the reader | %llu "
                     "datagrams, %llu per pass%s | %llu of %llu opened ahead",
                     (unsigned long long)stops, (unsigned long long)hy.link->c.tx_stop_paced,
                     (unsigned long long)hy.link->c.tx_stop_dry,
                     (unsigned long long)hy.link->c.tx_stop_blocked,
                     (unsigned long long)hy.link->c.tx_stop_yield,
                     (unsigned long long)hy.link->c.tx_packets,
                     (unsigned long long)(stops ? hy.link->c.tx_packets / stops : 0), stale, ahead,
                     ahead + missed);
            }
#endif
        }

        /* The shared connection, once per batch: what arrived on it is read, what the sessions
         * queued goes out, and its timers are honoured whether or not anything woke us. */
        hy_turn(loop);
#if LC_HYSTERIA
        /* And back on watch the moment there is room, because the turn above is what makes it: the
         * flush at the end of hy_turn is what empties the datagram queue. Left to any later point
         * this would be a socket nobody reads while the connection sits idle — the failure the gate
         * above is worth having only if it is always undone. */
        if (!udp_read_armed && udp_fd >= 0 &&
            !hy_udp_full() &&
            lc_loop_mod(loop, udp_fd, LC_EV_READ, &udp_tag) == 0)
            udp_read_armed = 1;
#endif

        /* After the batch, never during it: expiry ends sessions that events in this batch may have
         * been about, and the reap is what makes ending them safe. */
        sessions_expire(loop);
        if (listen_resume_at != 0u)
            accept_resume(loop, listen_fd, shared_listen_fd >= 0, lc_now_ms());
        /* After expiry, so that a pooled dial the sweep just gave up on is dialled again this turn,
         * and before the reap, which only frees memory. */
        pool_tick(loop);
        sessions_reap();
    }
    if (hy.on)
        hy_drop(loop);
    lc_loop_free(loop);
    close(listen_fd);
    return exit_rc;
}
