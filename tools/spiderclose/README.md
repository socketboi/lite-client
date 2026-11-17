# Controlled response-close oracle

Run `make HYSTERIA=0 check-spider-close` in the documented Linux build image,
with the pinned x/net vendor and its x/text dependency provisioned. `GO127`
defaults to `/usr/local/go1.27/bin/go`; the oracle requires Go 1.27.1 and rejects
the legacy HTTP/2 build tag. Dependencies are checked with `-mod=readonly`.

The optional gate compares the C production feed/Do/request/take/completion
drivers with the real, unmodified pinned Go transport. Go's channel barriers
and `testing/synctest` settle goroutines without scheduling sleeps. A net.Pipe
peer sends an unread 302 response with Content-Length 5000:

| Controlled order | CANCEL | Connection refund | Stream refund |
| --- | --- | --- | --- |
| END_STREAM and request cleanup before Body.Close | 0 | 5000 | 0 |
| Body.Close and request cleanup before DATA/END_STREAM | 1 | 5000 | 0 |
| END_STREAM while the already-selected reset Write is held | 1 | 5000 | 0 |

The reset gate holds an actual Go net.Conn.Write. Close must remain blocked
until that Write finishes; later END_STREAM does not retract its chosen CANCEL.
Both clients must finish cleanup and send exactly one connection-only refund,
with no duplicate reset or PING. Frame order between independent refund/reset
writers is not compared. C cases also run in the ordinary `make check` suite.
The paired gate keeps both client logs under BUILD and checks exact case
coverage as well as the values against the live Go observations.

The reference chain is `vendor/x-net/http2/transport_common.go::NewClientConn`
through `transport_wrap.go::newUserClientConn`, then Go 1.27.1
`src/net/http/internal/http2/transport.go::transportResponseBody.Close`,
`clientStream.cleanupWriteRequest` and `clientConnReadLoop.processData/endStream`.
The oracle does not patch these sources or replace the HTTP/2 transport.

These are forced, legal interleavings, not a traffic distribution or performance
experiment. They do not establish the cause of the ordinary bigbody CANCEL
frequency gap, alter checkpoint thresholds or close G2. They exercise HTTP/2
close semantics without REALITY/TLS; hardware execution and native acceptance
remain separate checks.
