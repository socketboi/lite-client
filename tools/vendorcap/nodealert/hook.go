// Copied into a copy of vendor/REALITY as zz_stand.go by run.sh: what the stand's node needs from
// inside the package, and nothing a node runs with. See run.sh.
package reality

import (
	"crypto"
	"hash"
	"net"

	"golang.org/x/crypto/cryptobyte"
)

// THE HANDSHAKE HALF, for the alps scenarios: a node whose EncryptedExtensions carries application
// settings, and that takes the EncryptedExtensions a client answers them with into the transcript
// before its Finished — what a server speaking ALPS does, and a stock node does not. run.sh splices
// five calls into this copy of the package: standALPSExt at the end of encryptedExtensionsMsg's
// marshal; standALPN where that message gets its protocol, because a REALITY node never chooses
// one — processClientHello, where Go negotiates it, is commented out of its handshake
// (vendor/REALITY/handshake_server_tls13.go:96-100) — so the stand names it; standALPSLen where the
// record is padded to the target's length (vendor/REALITY/conn.go:552-578), which the settings
// would otherwise overrun; standSavePre before the client's Finished is predicted, see standPre; and
// standTakeClientEE at the top of readClientFinished. Set before each
// connection by the node, which serves one at a time.
var (
	StandALPS     uint16 // the codepoint, 0 for none
	StandALPSData []byte // what the settings say
	StandALPN     string // the protocol to choose regardless of the config, "" to leave it
	StandClientEE []byte // what the client answered with, nil for nothing

	// What the handshake itself failed with. reality.Server reports every failure as "handshake did
	// not complete successfully", which hides the alert the client sent; this is the error under it.
	StandHandshakeErr error
)

func standALPSExt(b *cryptobyte.Builder) {
	if StandALPS != 0 {
		b.AddUint16(StandALPS)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(StandALPSData) })
	}
}

func standALPSLen() int {
	if StandALPS == 0 {
		return 0
	}
	return 4 + len(StandALPSData)
}

func standALPN(selected string) string {
	if StandALPN != "" {
		return StandALPN
	}
	return selected
}

// The transcript as it stood before the node PREDICTED the client's Finished. A Go server computes
// that Finished as soon as its own is out and hashes it straight into the transcript, for the
// resumption secret (vendor/REALITY/handshake_server_tls13.go:1062-1073) — so by the time the
// client's flight arrives the transcript already holds a Finished that assumed no EncryptedExtensions
// before it. The answer is hashed into this copy instead, and the expected Finished taken from it.
var standPre hash.Hash

func standSavePre(t hash.Hash, h crypto.Hash) { standPre = cloneHash(t, h) }

// standTakeClientEE takes an EncryptedExtensions, if that is what the client sent next, into the
// transcript and into StandClientEE, and says whether it did — the caller then recomputes the
// Finished it expects, which it had taken before this message existed.
func (c *Conn) standTakeClientEE(transcript hash.Hash) (bool, error) {
	if err := c.readHandshakeBytes(4); err != nil {
		return false, err
	}
	data := c.hand.Bytes()
	if data[0] != typeEncryptedExtensions {
		return false, nil
	}
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if err := c.readHandshakeBytes(4 + n); err != nil {
		return false, err
	}
	StandClientEE = append([]byte(nil), c.hand.Next(4+n)...)
	transcript.Write(StandClientEE)
	return true, nil
}

// StandRaw is the TCP connection under the TLS one, for bytes written past the record layer — what
// anybody on the path can put into the stream.
func (c *Conn) StandRaw() net.Conn { return c.conn }

// StandSeal writes ONE record of inner type typ holding data, sealed with the current write key.
//
// Any type and any content, empty included, which writeRecordLocked will not do: it writes nothing
// for empty data (vendor/REALITY/conn.go:1156), and this fork's encrypt refuses a handshake record
// it holds no target length for (vendor/REALITY/conn.go:553-574) — the lengths are the target's
// handshake, copied, and are cleared here for the one call.
func (c *Conn) StandSeal(typ byte, data []byte) error {
	c.out.Lock()
	defer c.out.Unlock()
	saved := c.out.handshakeLen
	c.out.handshakeLen = [7]int{}
	defer func() { c.out.handshakeLen = saved }()
	rec := []byte{typ, 3, 3, byte(len(data) >> 8), byte(len(data))}
	out, err := c.out.encrypt(rec, data, c.config.rand())
	if err != nil {
		return err
	}
	_, err = c.conn.Write(out)
	return err
}

// StandRotateWrite moves the write key one generation on, as the sender of a KeyUpdate does right
// after it (vendor/REALITY/conn.go:1431-1432 is the same two lines, for an answer).
func (c *Conn) StandRotateWrite() {
	c.out.Lock()
	defer c.out.Unlock()
	suite := cipherSuiteTLS13ByID(c.cipherSuite)
	c.out.setTrafficSecret(suite, QUICEncryptionLevelInitial, suite.nextTrafficSecret(c.out.trafficSecret))
}

// StandSealBare writes ONE record whose header says `outer` and whose inner plaintext is exactly
// `inner` — no content type appended, so it can be empty, all zeros, over 2^14 + 1, or sealed under
// a header that is not application_data. The node's own post-handshake records are built this way
// (vendor/REALITY/tls.go:421-431).
func (c *Conn) StandSealBare(outer byte, inner []byte) error {
	c.out.Lock()
	defer c.out.Unlock()
	a := c.out.cipher.(aead)
	n := len(inner) + a.Overhead()
	hdr := []byte{outer, 3, 3, byte(n >> 8), byte(n)}
	rec := a.Seal(hdr, c.out.seq[:], inner, hdr)
	c.out.incSeq()
	_, err := c.conn.Write(rec)
	return err
}

// StandInSecret is the read key's traffic secret as it stands, and StandReadGens how many
// generations the read key has moved on from `from` since — the KeyUpdates the node has taken from
// the client, each moving it one (vendor/REALITY/conn.go:1412-1413), or -1 for none of the next
// eight. For kufull, where the answer is somewhere among 48 MB of records and only the node's key
// can tell it from them.
func (c *Conn) StandInSecret() []byte {
	c.in.Lock()
	defer c.in.Unlock()
	return append([]byte(nil), c.in.trafficSecret...)
}

func (c *Conn) StandReadGens(from []byte) int {
	c.in.Lock()
	defer c.in.Unlock()
	suite := cipherSuiteTLS13ByID(c.cipherSuite)
	s := from
	for i := 0; i < 8; i++ {
		if string(s) == string(c.in.trafficSecret) {
			return i
		}
		s = suite.nextTrafficSecret(s)
	}
	return -1
}
