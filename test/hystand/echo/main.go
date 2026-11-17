// Echoes every byte back, unchanged. The node reaches it on its own loopback, so the only path the
// bytes travel that is ours is the tunnel: what comes back differing from what went out is the
// client's doing and nothing else's.
//
// AND A SECOND PORT THAT ANSWERS NOTHING, on 9001, for one question the echo port cannot be asked.
//
// Every transfer this stand makes is symmetric — the loader sends and reads the same bytes back — so
// both directions of the tunnel carry data at once, and a client's outgoing datagrams are a mixture
// of its own stream data and its acknowledgements for the other direction. That mixture is exactly
// what the shape measurement in loss.sh cannot separate: the reference puts three times as many
// small datagrams on the wire as this client, and "small at this MTU" means either a bare
// acknowledgement or a partial data packet, with no way to tell which from outside.
//
// A sink settles it. With nothing coming back, the far end sends only acknowledgements, and
// acknowledgements do not elicit acknowledgements — so a client uploading into this port has almost
// nothing to acknowledge. Whatever small datagrams it still emits are its own partial packets.
package main

import (
	"io"
	"log"
	"net"
)

// One byte back per megabyte swallowed, and nothing else.
//
// ⚠️ A SINK THAT ANSWERS NOTHING AT ALL CANNOT BE MEASURED AGAINST, which is what the first version
// of this was. With no reply the loader finishes the moment its local socket has accepted the bytes
// — 1 MB "in 0.00s at 9.9 Gbit/s" — while the tunnel is still carrying them, and the stand then
// tears the client down mid-transfer and reports the shape of whatever happened to have left. The
// answer has to come from the FAR side of the tunnel or it proves nothing.
//
// A megabyte is coarse enough to keep the point of the sink: sixteen bytes come back over a 16 MB
// upload, which is sixteen small datagrams against some forty thousand — 0.04 % — where an echo
// would have sent back every one of the sixteen million.
const mark = 1 << 20

func serve(addr string, back bool) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s (echo=%v)", addr, back)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			defer c.Close()
			if back {
				io.Copy(c, c)
				return
			}
			buf := make([]byte, 64*1024)
			var got, sent int64
			for {
				n, err := c.Read(buf)
				got += int64(n)
				for got/mark > sent {
					if _, werr := c.Write([]byte{'.'}); werr != nil {
						return
					}
					sent++
				}
				if err != nil {
					return
				}
			}
		}(c)
	}
}

func main() {
	go serve("127.0.0.1:9001", false)
	serve("127.0.0.1:9000", true)
}
