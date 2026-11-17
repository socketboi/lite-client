// Pushes a position-dependent pattern up the tunnel and checks every byte that comes back.
//
// The pattern is a function of the OFFSET, so a truncation, a duplicated chunk or a reordering
// shows as a mismatch at a named position rather than as a length that happens to agree.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

func at(i int) byte { return byte((i*7 + 13) & 0xff) }

func main() {
	addr := os.Args[1]
	n, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("usage: load ADDR BYTES")
		os.Exit(2)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(120 * time.Second))

	// A THIRD ARGUMENT, `sink`, FOR THE ONE QUESTION A ROUND TRIP CANNOT BE ASKED. The default is
	// what it always was — send, and read the same bytes back — because that is what proves the
	// tunnel carries bytes unchanged. With `sink` the far end is the port that answers nothing
	// (test/hystand/echo), so the tunnel carries ONE direction, and a client's outgoing datagrams
	// are its own data rather than a mixture of data and acknowledgements. loss.sh says what that
	// separation is for.
	sink := len(os.Args) > 3 && os.Args[3] == "sink"

	start := time.Now()
	bad := make(chan string, 1)

	if sink {
		// The sink's one byte per megabyte, read back so that "done" means the far side has it —
		// see test/hystand/echo. Without this the loader finishes at its own socket and the stand
		// measures a transfer that is still in flight.
		go func() {
			want := n / (1 << 20)
			if want == 0 {
				bad <- ""
				return
			}
			if _, err := io.ReadFull(c, make([]byte, want)); err != nil {
				bad <- fmt.Sprintf("the sink acknowledged %d of %d megabytes: %v", 0, want, err)
				return
			}
			bad <- ""
		}()
	} else {
		go func() {
			buf := make([]byte, 64*1024)
			off := 0
			for off < n {
				want := len(buf)
				if n-off < want {
					want = n - off
				}
				m, err := io.ReadFull(c, buf[:want])
				if err != nil {
					bad <- fmt.Sprintf("read stopped %d bytes in: %v", off+m, err)
					return
				}
				for i := 0; i < m; i++ {
					if buf[i] != at(off+i) {
						bad <- fmt.Sprintf("byte %d came back %02x, sent %02x", off+i, buf[i], at(off+i))
						return
					}
				}
				off += m
			}
			bad <- ""
		}()
	}

	out := make([]byte, 64*1024)
	for off := 0; off < n; {
		want := len(out)
		if n-off < want {
			want = n - off
		}
		for i := 0; i < want; i++ {
			out[i] = at(off + i)
		}
		m, err := c.Write(out[:want])
		if err != nil {
			fmt.Println("write:", err)
			os.Exit(1)
		}
		off += m
	}

	if msg := <-bad; msg != "" {
		fmt.Println("MISMATCH:", msg)
		os.Exit(1)
	}
	d := time.Since(start).Seconds()
	if sink {
		fmt.Printf("ok %d bytes up, nothing asked back, in %.2fs (%.1f Mbit/s one way)\n",
			n, d, float64(n)*8/d/1e6)
		return
	}
	fmt.Printf("ok %d bytes up and back, byte for byte, in %.2fs (%.1f Mbit/s round trip)\n",
		n, d, float64(n)*8*2/d/1e6)
}
