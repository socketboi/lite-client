// What the REALITY plane's reference says of a signature on a certificate — Go's own
// x509 checkSignature (GOROOT/src/crypto/x509/x509.go:1055-1141, go1.27.1, the toolchain Xray-core
// is built with), reached through the exported Certificate.CheckSignatureFrom. Writes
// test/gosig/reference.h, which test/gosig holds lc_go_check_signature (cert/gosig.c) to, error
// text for error text.
//
// NOTHING OF THE VERDICT IS REPLICATED HERE. checkSignature is unexported, and
// Certificate.CheckSignature cannot stand in for it: it passes allowSHA1=true
// (GOROOT/src/crypto/x509/x509.go:1028-1030), where Certificate.Verify's path passes false. So every
// vector is put to CheckSignatureFrom on a child/parent pair built for the purpose
// (x509.go:999-1019): the parent is a CA with no key usage, so the two constraint checks in front
// of checkSignature pass, and its PublicKeyAlgorithm is never Unknown, so the third does too; what
// comes back is checkSignature's own answer, with allowSHA1=false, through the real crypto/rsa,
// crypto/ecdsa, crypto/ed25519 and crypto/mldsa.
//
// WHAT IS REPLICATED is the other direction — making signatures. Go's signers refuse most of what
// needs testing (a padding byte off by one, a salt of the wrong length, an r of zero, a public key
// of small order) and since go1.26 ignore the random reader (GenerateKey), so nothing they produce
// would be the same twice. Keys are therefore generated here from a seeded ChaCha8 stream, RSA
// encodings (PKCS #1 v1.5 and EMSA-PSS) are built here and put through the raw private-key
// operation, ECDSA signatures are computed from the private scalar, and Ed25519 forgeries under
// small-order keys are found with a small big.Int model of the curve. Each constructed "valid"
// signature is asserted to be accepted by Go before it is written, and each constructed invalid one
// to be refused, so a mistake in this file stops the generation instead of producing a vector that
// tests nothing. One more thing is derived rather than observed: whether checkSignature reaches
// mldsa.Verify (sv_vecs[].ml_reach), which the C test uses to check its stand-in for the ML-DSA
// port; the words themselves are still Go's.
//
// GODEBUG: this module says `go 1.27`, as vendor/Xray-core/go.mod does, so rsa1024min has its
// go1.24+ default — keys under 1024 bits are refused (GOROOT/src/internal/godebugs/table.go:61).
// fips140 is off, as in any build that does not ask for it.
//
// Not built by the gate. Regenerate in the build image, from the repository root (a minute or so —
// most of it finding the primes of the 16384-bit key):
//
//	docker run --rm -v "$PWD:/w" -w /w lc-build:local sh -c 'cd tools/sigvec && \
//	  /usr/local/go1.27/bin/go run . > ../../test/gosig/reference.h'
package main

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	_ "crypto/sha1" // MGF1 with SHA-1, one of the PSS mistakes below
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"hash"
	"math/big"
	"math/rand/v2"
	"os"
	"runtime"
	"strings"
)

// ---- determinism -------------------------------------------------------------------------------

// A stream per label, so that adding a key or a vector does not move any other.
func stream(label string) *rand.Rand {
	return rand.New(rand.NewChaCha8(sha256.Sum256([]byte("tools/sigvec/" + label))))
}

func randBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func randBelow(r *rand.Rand, n *big.Int) *big.Int {
	for {
		v := new(big.Int).SetBytes(randBytes(r, (n.BitLen()+7)/8))
		v.Rsh(v, uint((n.BitLen()+7)/8*8-n.BitLen()))
		if v.Sign() > 0 && v.Cmp(n) < 0 {
			return v
		}
	}
}

func fill(v *big.Int, n int) []byte { return v.FillBytes(make([]byte, n)) }

func cat(p ...[]byte) []byte { return bytes.Join(p, nil) }

// ---- the keys and the vectors, as the C test will see them -------------------------------------

const (
	kNone = iota
	kRSA
	kDSA
	kECDSA
	kEd25519
	kMLDSA
)

type key struct {
	name  string
	kind  int
	pub   crypto.PublicKey
	pkAlg x509.PublicKeyAlgorithm

	n     []byte // RSA modulus, big-endian magnitude
	nNil  bool
	e     int64
	curve int    // 1..4 = P-224, P-256, P-384, P-521
	point []byte // ECDSA uncompressed point
	ed    []byte // Ed25519, 32 bytes
	ml    int    // 1..3 = ML-DSA-44, -65, -87
	mpk   []byte
}

type vec struct {
	what    string
	alg     x509.SignatureAlgorithm
	key     int
	msg     []byte
	sig     []byte
	want    string // "" = nil error
	mlReach bool
	mlInner string
}

var (
	keys []key
	vecs []vec
)

func addKey(k key) int {
	keys = append(keys, k)
	return len(keys) - 1
}

const (
	expectAny = iota
	expectOK
	expectBad
)

// goCheck is checkSignature(algo, signed, signature, pub, false), reached through CheckSignatureFrom.
func goCheck(alg x509.SignatureAlgorithm, k key, msg, sig []byte) error {
	parent := &x509.Certificate{BasicConstraintsValid: true, IsCA: true, PublicKeyAlgorithm: k.pkAlg, PublicKey: k.pub}
	child := &x509.Certificate{SignatureAlgorithm: alg, RawTBSCertificate: msg, Signature: sig}
	return child.CheckSignatureFrom(parent)
}

func add(expect int, what string, alg x509.SignatureAlgorithm, ki int, msg, sig []byte) {
	k := keys[ki]
	err := goCheck(alg, k, msg, sig)
	want := ""
	if err != nil {
		want = err.Error()
	}
	if expect == expectOK && err != nil {
		panic(fmt.Sprintf("%s: constructed as valid, Go says %v", what, err))
	}
	if expect == expectBad && err == nil {
		panic(fmt.Sprintf("%s: constructed as invalid, Go accepts it", what))
	}
	v := vec{what: what, alg: alg, key: ki, msg: msg, sig: sig, want: want}
	// Whether checkSignature gets as far as mldsa.Verify (x509.go:1115-1135), and what that said —
	// the one thing here derived rather than observed; see the header.
	if k.kind == kMLDSA && (alg == x509.MLDSA44 && k.ml == 1 || alg == x509.MLDSA65 && k.ml == 2 || alg == x509.MLDSA87 && k.ml == 3) {
		v.mlReach = true
		if e := mldsa.Verify(k.pub.(*mldsa.PublicKey), msg, sig, nil); e != nil {
			v.mlInner = e.Error()
		}
		if w := "x509: ML-DSA verification failure: " + v.mlInner; v.mlInner != "" && want != w || v.mlInner == "" && want != "" {
			panic(what + ": the ML-DSA dispatch is not what this file thinks it is: " + want)
		}
	}
	vecs = append(vecs, v)
}

// ---- RSA ---------------------------------------------------------------------------------------

type rsaPriv struct {
	n, d *big.Int
	e    int64
	bits int
	ki   int
}

func genPrime(r *rand.Rand, bits int, e int64) *big.Int {
	one := big.NewInt(1)
	for {
		p := new(big.Int).SetBytes(randBytes(r, (bits+7)/8))
		p.Rsh(p, uint((bits+7)/8*8-bits))
		p.SetBit(p, bits-1, 1)
		p.SetBit(p, bits-2, 1)
		p.SetBit(p, 0, 1)
		if e > 1 {
			pm1 := new(big.Int).Sub(p, one)
			if new(big.Int).GCD(nil, nil, pm1, big.NewInt(e)).Cmp(one) != 0 {
				continue
			}
		}
		if p.ProbablyPrime(0) {
			return p
		}
	}
}

// Two primes up to 4096 bits. Above that, 1024-bit primes and one to make up the size: finding a
// pair of 8192-bit primes takes the better part of an hour, and nothing on the verifying side can
// tell — Go checks neither the number of factors nor that there are any (checkPublicKey,
// GOROOT/src/crypto/internal/fips140/rsa/rsa.go:326-364), and d = e⁻¹ mod λ(N) signs all the same.
func genRSA(label string, bits int, e int64) *rsaPriv {
	r := stream("rsa/" + label)
	one := big.NewInt(1)
	for {
		var primes []*big.Int
		if bits <= 4096 {
			primes = []*big.Int{genPrime(r, (bits+1)/2, e), genPrime(r, bits/2, e)}
		} else {
			prod := big.NewInt(1)
			for prod.BitLen() < bits-1536 {
				p := genPrime(r, 1024, e)
				primes = append(primes, p)
				prod.Mul(prod, p)
			}
			// The last one sized so that the product can come out exactly `bits` long.
			for try := 0; ; try++ {
				s := bits - prod.BitLen() + try%2
				q := genPrime(r, s, e)
				if new(big.Int).Mul(prod, q).BitLen() == bits {
					primes = append(primes, q)
					break
				}
			}
		}
		n := big.NewInt(1)
		lambda := big.NewInt(1)
		distinct := map[string]bool{}
		for _, p := range primes {
			distinct[p.String()] = true
			n.Mul(n, p)
			pm1 := new(big.Int).Sub(p, one)
			g := new(big.Int).GCD(nil, nil, lambda, pm1)
			lambda.Div(new(big.Int).Mul(lambda, pm1), g)
		}
		if len(distinct) != len(primes) || n.BitLen() != bits {
			continue
		}
		d := new(big.Int).ModInverse(big.NewInt(e), lambda)
		if d == nil {
			continue
		}
		k := &rsaPriv{n: n, d: d, e: e, bits: bits}
		k.ki = addKey(key{name: label, kind: kRSA, pkAlg: x509.RSA, pub: &rsa.PublicKey{N: n, E: int(e)}, n: n.Bytes(), e: e})
		return k
	}
}

// An RSA public key with no private half: N and E exactly as given.
func rsaPub(label string, n *big.Int, e int64) int {
	k := key{name: label, kind: kRSA, pkAlg: x509.RSA, e: e}
	if n == nil {
		k.nNil = true
		k.pub = &rsa.PublicKey{N: nil, E: int(e)}
	} else {
		k.n = n.Bytes()
		k.pub = &rsa.PublicKey{N: n, E: int(e)}
	}
	return addKey(k)
}

func (k *rsaPriv) size() int { return (k.bits + 7) / 8 }

// The raw private-key operation on an encoded message of any length up to k bytes; ok is false
// when the message is not below N and so cannot be signed.
func (k *rsaPriv) raw(em []byte) ([]byte, bool) {
	m := new(big.Int).SetBytes(em)
	if m.Cmp(k.n) >= 0 {
		return nil, false
	}
	return fill(new(big.Int).Exp(m, k.d, k.n), k.size()), true
}

type hinfo struct {
	h      crypto.Hash
	name   string
	prefix []byte
	pkcs   x509.SignatureAlgorithm
	pss    x509.SignatureAlgorithm
	ecdsa  x509.SignatureAlgorithm
}

// The DigestInfo prefixes, as GOROOT/src/crypto/internal/fips140/rsa/pkcs1v15.go:28-43 has them.
var hashes = []hinfo{
	{crypto.SHA256, "SHA-256", []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}, x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256},
	{crypto.SHA384, "SHA-384", []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}, x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384},
	{crypto.SHA512, "SHA-512", []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}, x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512},
}

func digest(h crypto.Hash, msg []byte) []byte {
	x := h.New()
	x.Write(msg)
	return x.Sum(nil)
}

func pkcs1EM(k int, prefix, d []byte) []byte {
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-len(prefix)-len(d)-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-len(prefix)-len(d):], prefix)
	copy(em[k-len(d):], d)
	return em
}

func mgf1XOR(out []byte, h hash.Hash, seed []byte) {
	var counter [4]byte
	for done := 0; done < len(out); {
		h.Reset()
		h.Write(seed)
		h.Write(counter[:])
		dg := h.Sum(nil)
		for i := 0; i < len(dg) && done < len(out); i++ {
			out[done] ^= dg[i]
			done++
		}
		for i := 3; i >= 0; i-- {
			if counter[i]++; counter[i] != 0 {
				break
			}
		}
	}
}

type pssOpt struct {
	salt    []byte
	hH      crypto.Hash     // the hash of M' (normally the signature's)
	mgfH    crypto.Hash     // MGF1's hash (normally the signature's)
	mHash   []byte          // the digest put in M' (normally the right one)
	dbMut   func(db []byte) // before masking
	emMut   func(em []byte) // after the whole encoding
	keepTop bool            // do not clear the leftmost bits of maskedDB
}

// EMSA-PSS-Encode (RFC 8017 §9.1.1), with each step open to a mistake.
func pssEM(emBits int, o pssOpt) []byte {
	hLen := o.hH.Size()
	emLen := (emBits + 7) / 8
	sLen := len(o.salt)
	if emLen < hLen+sLen+2 {
		return nil
	}
	em := make([]byte, emLen)
	psLen := emLen - sLen - hLen - 2
	db := em[:emLen-hLen-1]
	hh := em[emLen-hLen-1 : emLen-1]
	x := o.hH.New()
	x.Write(make([]byte, 8))
	x.Write(o.mHash)
	x.Write(o.salt)
	copy(hh, x.Sum(nil))
	db[psLen] = 1
	copy(db[psLen+1:], o.salt)
	if o.dbMut != nil {
		o.dbMut(db)
	}
	mgf1XOR(db, o.mgfH.New(), hh)
	if !o.keepTop {
		db[0] &= 0xff >> (8*emLen - emBits)
	}
	em[emLen-1] = 0xbc
	if o.emMut != nil {
		o.emMut(em)
	}
	return em
}

func (k *rsaPriv) signPSS(o pssOpt, lead func(full []byte)) ([]byte, bool) {
	em := pssEM(k.bits-1, o)
	if em == nil {
		return nil, false
	}
	full := make([]byte, k.size())
	copy(full[k.size()-len(em):], em)
	if lead != nil {
		lead(full)
	}
	return k.raw(full)
}

func (k *rsaPriv) validPSS(h hinfo, msg []byte) ([]byte, bool) {
	r := stream(fmt.Sprintf("pss-salt/%d/%s", k.ki, h.name))
	return k.signPSS(pssOpt{salt: randBytes(r, h.h.Size()), hH: h.h, mgfH: h.h, mHash: digest(h.h, msg)}, nil)
}

func (k *rsaPriv) validPKCS(h hinfo, msg []byte) []byte {
	s, ok := k.raw(pkcs1EM(k.size(), h.prefix, digest(h.h, msg)))
	if !ok {
		panic("PKCS #1 v1.5 encoding at or above N")
	}
	return s
}

func rsaVectors(msg, other []byte) {
	sizes := []int{1024, 1025, 1031, 1033, 1536, 2047, 2048, 2049, 3072, 4096, 4097, 8200, 16384}
	keysBySize := map[int]*rsaPriv{}
	for _, b := range sizes {
		keysBySize[b] = genRSA(fmt.Sprintf("rsa%d-e65537", b), b, 65537)
	}
	k2048 := keysBySize[2048]

	// A first check of this file's PKCS #1 v1.5 encoder against Go's own verifier, before any vector.
	{
		if err := rsa.VerifyPKCS1v15(&rsa.PublicKey{N: k2048.n, E: 65537}, crypto.SHA256, digest(crypto.SHA256, msg), k2048.validPKCS(hashes[0], msg)); err != nil {
			panic("this file's PKCS #1 v1.5 is not Go's: " + err.Error())
		}
	}

	// Every size, every hash, both schemes.
	for _, b := range sizes {
		k := keysBySize[b]
		for _, h := range hashes {
			add(expectOK, fmt.Sprintf("RSA-%d e=65537 %s PKCS#1 v1.5 valid", b, h.name), h.pkcs, k.ki, msg, k.validPKCS(h, msg))
			if s, ok := k.validPSS(h, msg); ok {
				add(expectOK, fmt.Sprintf("RSA-%d e=65537 %s PSS valid", b, h.name), h.pss, k.ki, msg, s)
			} else {
				// emLen < hLen+sLen+2: no signature of this shape exists for the key; any is refused.
				s, _ := k.raw(randBytes(stream(fmt.Sprintf("junk/%d", b)), k.size()-1))
				add(expectBad, fmt.Sprintf("RSA-%d %s PSS: the key is too small for the salt and the hash", b, h.name), h.pss, k.ki, msg, s)
			}
			add(expectBad, fmt.Sprintf("RSA-%d %s PKCS#1 v1.5 over another message", b, h.name), h.pkcs, k.ki, other, k.validPKCS(h, msg))
		}
		// modBits-1 a multiple of 8: EM is one byte shorter than N, and the byte in front must be 0.
		if (b-1)%8 == 0 {
			h := hashes[0]
			r := stream(fmt.Sprintf("pss-lead/%d", b))
			s, ok := k.signPSS(pssOpt{salt: randBytes(r, 32), hH: h.h, mgfH: h.h, mHash: digest(h.h, msg)}, func(full []byte) { full[0] = 1 })
			if ok {
				add(expectBad, fmt.Sprintf("RSA-%d PSS: a nonzero byte in front of a one-byte-short EM", b), h.pss, k.ki, msg, s)
			}
		} else {
			// The leftmost 8·emLen−emBits bits of EM must be zero: set the highest of them.
			h := hashes[0]
			emBits := b - 1
			emLen := (emBits + 7) / 8
			top := 8*emLen - emBits
			r := stream(fmt.Sprintf("pss-top/%d", b))
			s, ok := k.signPSS(pssOpt{salt: randBytes(r, 32), hH: h.h, mgfH: h.h, mHash: digest(h.h, msg),
				emMut: func(em []byte) { em[0] |= byte(1) << (8 - top) }}, nil)
			if ok {
				add(expectBad, fmt.Sprintf("RSA-%d PSS: the lowest of the bits above emBits set", b), h.pss, k.ki, msg, s)
			}
			s, ok = k.signPSS(pssOpt{salt: randBytes(r, 32), hH: h.h, mgfH: h.h, mHash: digest(h.h, msg), keepTop: true}, nil)
			if ok {
				add(expectAny, fmt.Sprintf("RSA-%d PSS: the mask's bits above emBits left in", b), h.pss, k.ki, msg, s)
			}
		}
	}

	// ---- PKCS #1 v1.5 padding, one byte at a time, on the 2048-bit key and an odd-sized one ----
	for _, k := range []*rsaPriv{k2048, keysBySize[1031], keysBySize[4097]} {
		h := hashes[0]
		d := digest(h.h, msg)
		size := k.size()
		muts := []struct {
			what string
			em   func() []byte
		}{
			{"first byte 01", func() []byte { e := pkcs1EM(size, h.prefix, d); e[0] = 1; return e }},
			{"block type 02", func() []byte { e := pkcs1EM(size, h.prefix, d); e[1] = 2; return e }},
			{"block type 00", func() []byte { e := pkcs1EM(size, h.prefix, d); e[1] = 0; return e }},
			{"first PS byte fe", func() []byte { e := pkcs1EM(size, h.prefix, d); e[2] = 0xfe; return e }},
			{"last PS byte fe", func() []byte { e := pkcs1EM(size, h.prefix, d); e[size-len(h.prefix)-len(d)-2] = 0xfe; return e }},
			{"separator 01", func() []byte { e := pkcs1EM(size, h.prefix, d); e[size-len(h.prefix)-len(d)-1] = 1; return e }},
			{"separator ff (PS one longer, no zero)", func() []byte { e := pkcs1EM(size, h.prefix, d); e[size-len(h.prefix)-len(d)-1] = 0xff; return e }},
			{"PS one byte short, T one byte early, trailing 00", func() []byte {
				e := pkcs1EM(size, h.prefix, d)
				t := cat(e[size-len(h.prefix)-len(d)-1:], []byte{0})
				copy(e[size-len(h.prefix)-len(d)-2:], t)
				return e[:size]
			}},
			{"DigestInfo without the NULL parameters", func() []byte {
				pre := []byte{0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20}
				return pkcs1EM(size, pre, d)
			}},
			{"SHA-384 DigestInfo prefix around a SHA-256 digest", func() []byte { return pkcs1EM(size, hashes[1].prefix, d) }},
			{"DigestInfo length byte off by one", func() []byte {
				pre := bytes.Clone(h.prefix)
				pre[1]++
				return pkcs1EM(size, pre, d)
			}},
			{"no DigestInfo at all", func() []byte { return pkcs1EM(size, nil, d) }},
			{"digest with its last bit flipped", func() []byte { dd := bytes.Clone(d); dd[31] ^= 1; return pkcs1EM(size, h.prefix, dd) }},
			{"digest with its first bit flipped", func() []byte { dd := bytes.Clone(d); dd[0] ^= 0x80; return pkcs1EM(size, h.prefix, dd) }},
			{"all zero", func() []byte { return make([]byte, size) }},
			{"one", func() []byte { e := make([]byte, size); e[size-1] = 1; return e }},
		}
		for _, m := range muts {
			if s, ok := k.raw(m.em()); ok {
				add(expectBad, fmt.Sprintf("RSA-%d PKCS#1 v1.5: %s", k.bits, m.what), h.pkcs, k.ki, msg, s)
			}
		}
		valid := k.validPKCS(h, msg)
		nb := fill(k.n, size)
		nm1 := fill(new(big.Int).Sub(k.n, big.NewInt(1)), size)
		np1 := new(big.Int).Add(k.n, big.NewInt(1))
		sigs := []struct {
			what string
			sig  []byte
		}{
			{"signature one byte short", valid[1:]},
			{"signature with a zero byte in front", cat([]byte{0}, valid)},
			{"signature with a zero byte behind", cat(valid, []byte{0})},
			{"signature cut by one byte at the end", valid[:size-1]},
			{"signature = N", nb},
			{"signature = N-1", nm1},
			{"signature = N+1", fill(np1, size)},
			{"signature = 2^(8k)-1", bytes.Repeat([]byte{0xff}, size)},
			{"signature = 0", make([]byte, size)},
			{"signature = 1", fill(big.NewInt(1), size)},
			{"signature + N", new(big.Int).Add(new(big.Int).SetBytes(valid), k.n).Bytes()},
			{"empty signature", nil},
			{"last signature bit flipped", func() []byte { s := bytes.Clone(valid); s[size-1] ^= 1; return s }()},
		}
		for _, s := range sigs {
			add(expectBad, fmt.Sprintf("RSA-%d PKCS#1 v1.5: %s", k.bits, s.what), h.pkcs, k.ki, msg, s.sig)
		}
		// Right signature, wrong algorithm: another hash, and PSS.
		add(expectBad, fmt.Sprintf("RSA-%d SHA-256 PKCS#1 v1.5 signature under SHA384-RSA", k.bits), x509.SHA384WithRSA, k.ki, msg, valid)
		add(expectBad, fmt.Sprintf("RSA-%d SHA-256 PKCS#1 v1.5 signature under SHA256-RSAPSS", k.bits), x509.SHA256WithRSAPSS, k.ki, msg, valid)
		if s, ok := k.validPSS(h, msg); ok {
			add(expectBad, fmt.Sprintf("RSA-%d SHA-256 PSS signature under SHA256-RSA", k.bits), x509.SHA256WithRSA, k.ki, msg, s)
			add(expectBad, fmt.Sprintf("RSA-%d SHA-256 PSS signature under SHA384-RSAPSS", k.bits), x509.SHA384WithRSAPSS, k.ki, msg, s)
		}
	}

	// ---- PSS, one rule at a time ----
	for _, k := range []*rsaPriv{k2048, keysBySize[1031], keysBySize[1025], keysBySize[2049], keysBySize[1024]} {
		for _, h := range hashes {
			d := digest(h.h, msg)
			hl := h.h.Size()
			r := stream(fmt.Sprintf("pss-muts/%d/%s", k.bits, h.name))
			salt := randBytes(r, hl)
			base := func() pssOpt { return pssOpt{salt: salt, hH: h.h, mgfH: h.h, mHash: d} }
			emBits := k.bits - 1
			emLen := (emBits + 7) / 8
			maxSalt := emLen - hl - 2
			muts := []struct {
				what   string
				expect int
				o      pssOpt
			}{
				{"salt of zero bytes", expectBad, func() pssOpt { o := base(); o.salt = nil; return o }()},
				{"salt one byte short of the hash", expectBad, func() pssOpt { o := base(); o.salt = salt[:hl-1]; return o }()},
				{"salt one byte longer than the hash", expectBad, func() pssOpt { o := base(); o.salt = cat(salt, []byte{7}); return o }()},
				{"salt as long as it can be", expectAny, func() pssOpt { o := base(); o.salt = randBytes(r, maxSalt); return o }()},
				{"trailer bd", expectBad, func() pssOpt { o := base(); o.emMut = func(em []byte) { em[len(em)-1] = 0xbd }; return o }()},
				{"trailer 00", expectBad, func() pssOpt { o := base(); o.emMut = func(em []byte) { em[len(em)-1] = 0 }; return o }()},
				{"separator 00", expectBad, func() pssOpt { o := base(); o.dbMut = func(db []byte) { db[len(db)-hl-1] = 0 }; return o }()},
				{"separator 02", expectBad, func() pssOpt { o := base(); o.dbMut = func(db []byte) { db[len(db)-hl-1] = 2 }; return o }()},
				{"first PS byte 01", expectBad, func() pssOpt { o := base(); o.dbMut = func(db []byte) { db[0] ^= 1 }; return o }()},
				{"last PS byte 80", expectBad, func() pssOpt { o := base(); o.dbMut = func(db []byte) { db[len(db)-hl-2] = 0x80 }; return o }()},
				{"H over another digest", expectBad, func() pssOpt { o := base(); o.mHash = digest(h.h, other); return o }()},
				{"H over a digest of the right message by another hash", expectBad, func() pssOpt {
					o := base()
					if h.h == crypto.SHA256 {
						x := sha512.Sum512_256(msg)
						o.mHash = x[:]
					} else {
						o.mHash = digest(crypto.SHA256, msg)
					}
					return o
				}()},
				{"MGF1 with SHA-1", expectBad, func() pssOpt { o := base(); o.mgfH = crypto.SHA1; return o }()},
				{"H with a flipped bit", expectBad, func() pssOpt {
					o := base()
					o.emMut = func(em []byte) { em[len(em)-2] ^= 1 }
					return o
				}()},
				{"salt with a flipped bit after masking", expectBad, func() pssOpt {
					o := base()
					o.emMut = func(em []byte) { em[len(em)-hl-2] ^= 1 }
					return o
				}()},
			}
			for _, m := range muts {
				if s, ok := k.signPSS(m.o, nil); ok {
					add(m.expect, fmt.Sprintf("RSA-%d %s PSS: %s", k.bits, h.name, m.what), h.pss, k.ki, msg, s)
				}
			}
			if s, ok := k.validPSS(h, msg); ok {
				add(expectBad, fmt.Sprintf("RSA-%d %s PSS: signature one byte short", k.bits, h.name), h.pss, k.ki, msg, s[1:])
				add(expectBad, fmt.Sprintf("RSA-%d %s PSS: signature with a zero byte in front", k.bits, h.name), h.pss, k.ki, msg, cat([]byte{0}, s))
				add(expectBad, fmt.Sprintf("RSA-%d %s PSS: signature = N", k.bits, h.name), h.pss, k.ki, msg, fill(k.n, k.size()))
				add(expectBad, fmt.Sprintf("RSA-%d %s PSS: over another message", k.bits, h.name), h.pss, k.ki, other, s)
			}
		}
	}

	// ---- other exponents, with signatures ----
	for _, e := range []int64{3, 5, 17, 257, 1<<31 - 1} {
		k := genRSA(fmt.Sprintf("rsa2048-e%d", e), 2048, e)
		for _, h := range hashes {
			add(expectOK, fmt.Sprintf("RSA-2048 e=%d %s PKCS#1 v1.5 valid", e, h.name), h.pkcs, k.ki, msg, k.validPKCS(h, msg))
			s, _ := k.validPSS(h, msg)
			add(expectOK, fmt.Sprintf("RSA-2048 e=%d %s PSS valid", e, h.name), h.pss, k.ki, msg, s)
		}
		add(expectBad, fmt.Sprintf("RSA-2048 e=%d PKCS#1 v1.5 flipped bit", e), x509.SHA256WithRSA, k.ki, msg,
			func() []byte { s := k.validPKCS(hashes[0], msg); s[100] ^= 4; return s }())
	}
	// e=3 on an odd-sized key, where a cube root attack would bite a lax parser.
	{
		k := genRSA("rsa1031-e3", 1031, 3)
		add(expectOK, "RSA-1031 e=3 SHA-256 PKCS#1 v1.5 valid", x509.SHA256WithRSA, k.ki, msg, k.validPKCS(hashes[0], msg))
		// A "signature" whose cube starts with the right prefix and is garbage after the digest.
		em := pkcs1EM(k.size(), hashes[0].prefix, digest(crypto.SHA256, msg))
		em = cat(em[:k.size()-60], bytes.Repeat([]byte{0}, 60))
		if s, ok := k.raw(em); ok {
			add(expectBad, "RSA-1031 e=3 PKCS#1 v1.5: digest replaced by zeros", x509.SHA256WithRSA, k.ki, msg, s)
		}
	}

	// ---- keys refused before any arithmetic, and in which order ----
	valid := k2048.validPKCS(hashes[0], msg)
	validPSS, _ := k2048.validPSS(hashes[0], msg)
	n2048 := k2048.n
	even := new(big.Int).Add(n2048, big.NewInt(1))
	type pk struct {
		what string
		n    *big.Int
		e    int64
	}
	small := genRSA("rsa512-e65537", 512, 65537)
	k1016 := genRSA("rsa1016-e65537", 1016, 65537)
	k1023 := genRSA("rsa1023-e65537", 1023, 65537)
	pks := []pk{
		{"N nil", nil, 65537},
		{"N nil, e even", nil, 4},
		{"N = 0", big.NewInt(0), 65537},
		{"N = 1", big.NewInt(1), 65537},
		{"N = 3", big.NewInt(3), 3},
		{"N 512 bits", small.n, 65537},
		{"N 1016 bits", k1016.n, 65537},
		{"N 1023 bits", k1023.n, 65537},
		{"N 1023 bits, e even", k1023.n, 65536},
		{"N 2^1023 (1024 bits, even)", new(big.Int).Lsh(big.NewInt(1), 1023), 65537},
		{"N 2^1023+1 (1024 bits, odd)", new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 1023), big.NewInt(1)), 65537},
		{"N 1022 bits even, e 1", new(big.Int).Lsh(big.NewInt(3), 1020), 1},
		{"N even", even, 65537},
		{"N even, e even", even, 65536},
		{"N even, e 1", even, 1},
		{"e = 1", n2048, 1},
		{"e = 0", n2048, 0},
		{"e = -1", n2048, -1},
		{"e = -65537", n2048, -65537},
		{"e = 2", n2048, 2},
		{"e = 65536", n2048, 65536},
		{"e = 2^31-1 (the largest allowed), wrong for this N", n2048, 1<<31 - 1},
		{"e = 2^31 (even and too large)", n2048, 1 << 31},
		{"e = 2^31+1", n2048, 1<<31 + 1},
		{"e = 2^32+1", n2048, 1<<32 + 1},
		{"e = 2^62+1", n2048, 1<<62 + 1},
		{"e = 2^63-1", n2048, 1<<63 - 1},
		{"e = 3, wrong for this N", n2048, 3},
	}
	for _, p := range pks {
		ki := rsaPub("rsa-"+p.what, p.n, p.e)
		for _, alg := range []x509.SignatureAlgorithm{x509.SHA256WithRSA, x509.SHA256WithRSAPSS} {
			sig := valid
			if alg == x509.SHA256WithRSAPSS {
				sig = validPSS
			}
			add(expectBad, fmt.Sprintf("RSA key %s, %v", p.what, alg), alg, ki, msg, sig)
		}
	}
	// A key under 1024 bits with a signature that would be valid for it.
	for _, k := range []*rsaPriv{small, k1016, k1023} {
		add(expectBad, fmt.Sprintf("RSA-%d, a signature valid for it", k.bits), x509.SHA256WithRSA, k.ki, msg, k.validPKCS(hashes[0], msg))
		if s, ok := k.validPSS(hashes[0], msg); ok {
			add(expectBad, fmt.Sprintf("RSA-%d, a PSS signature valid for it", k.bits), x509.SHA256WithRSAPSS, k.ki, msg, s)
		}
	}
	// N with a zero byte in front as the parser hands it on (its Bytes() drop it anyway).
	{
		ki := addKey(key{name: "rsa2048 with a leading zero byte", kind: kRSA, pkAlg: x509.RSA, pub: &rsa.PublicKey{N: n2048, E: 65537},
			n: cat([]byte{0}, n2048.Bytes()), e: 65537})
		add(expectOK, "RSA-2048 whose modulus bytes carry a zero in front", x509.SHA256WithRSA, ki, msg, valid)
	}
}

// ---- ECDSA -------------------------------------------------------------------------------------

type ecKey struct {
	c    elliptic.Curve
	id   int
	d    *big.Int
	x, y *big.Int
	ki   int
}

var curves = []struct {
	id   int
	name string
	c    elliptic.Curve
}{{1, "P-224", elliptic.P224()}, {2, "P-256", elliptic.P256()}, {3, "P-384", elliptic.P384()}, {4, "P-521", elliptic.P521()}}

func ecPoint(c elliptic.Curve, x, y *big.Int) []byte {
	n := (c.Params().BitSize + 7) / 8
	return cat([]byte{4}, fill(x, n), fill(y, n))
}

func ecPubKey(label string, id int, c elliptic.Curve, x, y *big.Int, point []byte) int {
	return addKey(key{name: label, kind: kECDSA, pkAlg: x509.ECDSA, pub: &ecdsa.PublicKey{Curve: c, X: x, Y: y}, curve: id, point: point})
}

func newEC(label string, id int, c elliptic.Curve, d *big.Int) *ecKey {
	x, y := c.ScalarBaseMult(fill(d, (c.Params().N.BitLen()+7)/8))
	k := &ecKey{c: c, id: id, d: d, x: x, y: y}
	k.ki = ecPubKey(label, id, c, x, y, ecPoint(c, x, y))
	return k
}

// hashToInt as crypto/ecdsa has it (bits2int, then used modulo N).
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}
	ret := new(big.Int).SetBytes(hash)
	if excess := len(hash)*8 - orderBits; excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func (k *ecKey) sign(e *big.Int, nonce *big.Int) (r, s *big.Int) {
	n := k.c.Params().N
	rx, _ := k.c.ScalarBaseMult(fill(nonce, (n.BitLen()+7)/8))
	r = new(big.Int).Mod(rx, n)
	s = new(big.Int).Mul(r, k.d)
	s.Add(s, e)
	s.Mul(s, new(big.Int).ModInverse(nonce, n))
	s.Mod(s, n)
	return
}

// The DER of an INTEGER as cryptobyte wants it, and SEQUENCE { r, s }.
func derInt(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = cat([]byte{0}, b)
	}
	return tlv(0x02, b)
}

func tlv(tag byte, body []byte) []byte {
	n := len(body)
	switch {
	case n < 0x80:
		return cat([]byte{tag, byte(n)}, body)
	case n < 0x100:
		return cat([]byte{tag, 0x81, byte(n)}, body)
	default:
		return cat([]byte{tag, 0x82, byte(n >> 8), byte(n)}, body)
	}
}

func derSig(r, s *big.Int) []byte { return tlv(0x30, cat(derInt(r), derInt(s))) }

func ecdsaVectors(msg, other []byte) {
	for _, cv := range curves {
		c := cv.c
		n := c.Params().N
		r := stream("ecdsa/" + cv.name)
		k := newEC("ecdsa-"+cv.name, cv.id, c, randBelow(r, n))
		for _, h := range hashes {
			e := hashToInt(digest(h.h, msg), c)
			rr, ss := k.sign(e, randBelow(r, n))
			add(expectOK, fmt.Sprintf("ECDSA %s %s valid", cv.name, h.name), h.ecdsa, k.ki, msg, derSig(rr, ss))
			add(expectOK, fmt.Sprintf("ECDSA %s %s valid with s' = n-s", cv.name, h.name), h.ecdsa, k.ki, msg, derSig(rr, new(big.Int).Sub(n, ss)))
			add(expectBad, fmt.Sprintf("ECDSA %s %s over another message", cv.name, h.name), h.ecdsa, k.ki, other, derSig(rr, ss))
			add(expectBad, fmt.Sprintf("ECDSA %s %s under the next hash", cv.name, h.name), map[crypto.Hash]x509.SignatureAlgorithm{
				crypto.SHA256: x509.ECDSAWithSHA384, crypto.SHA384: x509.ECDSAWithSHA512, crypto.SHA512: x509.ECDSAWithSHA256}[h.h], k.ki, msg, derSig(rr, ss))
		}
		// Go's own RFC 6979 signer, as a check on this file's arithmetic.
		{
			priv, err := ecdsa.ParseRawPrivateKey(c, fill(k.d, (n.BitLen()+7)/8))
			if err != nil {
				panic(err)
			}
			dg := digest(crypto.SHA384, msg)
			sig, err := priv.Sign(nil, dg, crypto.SHA384)
			if err != nil {
				panic(err)
			}
			add(expectOK, fmt.Sprintf("ECDSA %s SHA-384 by Go's RFC 6979 signer", cv.name), x509.ECDSAWithSHA384, k.ki, msg, sig)
		}

		// The signature's DER and the range of r and s, on SHA-256.
		e := hashToInt(digest(crypto.SHA256, msg), c)
		rr, ss := k.sign(e, randBelow(r, n))
		alg := x509.ECDSAWithSHA256
		good := derSig(rr, ss)
		body := cat(derInt(rr), derInt(ss))
		plus := func(v *big.Int, w *big.Int) *big.Int { return new(big.Int).Add(v, w) }
		neg := func(v *big.Int) []byte { // two's complement of -v, minimally
			b := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(len(v.Bytes())*8+8)), v).Bytes()
			for len(b) > 1 && b[0] == 0xff && b[1]&0x80 != 0 {
				b = b[1:]
			}
			return tlv(0x02, b)
		}
		p := c.Params().P
		cases := []struct {
			what string
			sig  []byte
		}{
			{"r with a redundant zero byte", tlv(0x30, cat(tlv(0x02, cat([]byte{0}, derInt(rr)[2:])), derInt(ss)))},
			{"s with a redundant zero byte", tlv(0x30, cat(derInt(rr), tlv(0x02, cat([]byte{0}, derInt(ss)[2:]))))},
			{"r as a negative number", tlv(0x30, cat(neg(rr), derInt(ss)))},
			{"s as a negative number", tlv(0x30, cat(derInt(rr), neg(ss)))},
			{"r = 0", derSig(big.NewInt(0), ss)},
			{"s = 0", derSig(rr, big.NewInt(0))},
			{"r = 0 as an empty INTEGER", tlv(0x30, cat([]byte{0x02, 0x00}, derInt(ss)))},
			{"r = n", derSig(n, ss)},
			{"s = n", derSig(rr, n)},
			{"r + n", derSig(plus(rr, n), ss)},
			{"s + n", derSig(rr, plus(ss, n))},
			{"r = n-1", derSig(new(big.Int).Sub(n, big.NewInt(1)), ss)},
			{"r = 1", derSig(big.NewInt(1), ss)},
			{"s = 1", derSig(rr, big.NewInt(1))},
			{"r = p", derSig(p, ss)},
			{"r = 2^(8*len)", derSig(new(big.Int).Lsh(big.NewInt(1), uint(len(rr.Bytes())*8)), ss)},
			{"r and s swapped", derSig(ss, rr)},
			{"a byte after the SEQUENCE", cat(good, []byte{0})},
			{"a byte inside the SEQUENCE after s", tlv(0x30, cat(body, []byte{0}))},
			{"a third INTEGER", tlv(0x30, cat(body, derInt(big.NewInt(1))))},
			{"only r", tlv(0x30, derInt(rr))},
			{"SEQUENCE tag 10 (primitive)", func() []byte { b := bytes.Clone(good); b[0] = 0x10; return b }()},
			{"SET instead of SEQUENCE", func() []byte { b := bytes.Clone(good); b[0] = 0x31; return b }()},
			{"high-tag-number form", cat([]byte{0x3f}, good[1:])},
			{"r's tag 03", tlv(0x30, cat(tlv(0x03, derInt(rr)[2:]), derInt(ss)))},
			{"r's tag 22 (constructed INTEGER)", tlv(0x30, cat(tlv(0x22, derInt(rr)[2:]), derInt(ss)))},
			{"SEQUENCE length in long form when short would do", func() []byte {
				if len(body) >= 0x80 {
					return cat([]byte{0x30, 0x82, 0x00, byte(len(body))}, body)
				}
				return cat([]byte{0x30, 0x81, byte(len(body))}, body)
			}()},
			{"SEQUENCE length indefinite", cat([]byte{0x30, 0x80}, body, []byte{0, 0})},
			{"SEQUENCE length of five octets", cat([]byte{0x30, 0x85, 0, 0, 0, 0, byte(len(body))}, body)},
			{"INTEGER length in long form", tlv(0x30, cat([]byte{0x02, 0x81, byte(len(derInt(rr)) - 2)}, derInt(rr)[2:], derInt(ss)))},
			{"SEQUENCE one byte longer than what follows", func() []byte { b := bytes.Clone(good); b[len(b)-len(body)-1]++; return b }()},
			{"SEQUENCE one byte shorter than its contents", func() []byte { b := bytes.Clone(good); b[len(b)-len(body)-1]--; return b }()},
			{"last byte cut", good[:len(good)-1]},
			{"empty", nil},
			{"30 00", []byte{0x30, 0x00}},
			{"a single zero byte", []byte{0}},
			{"30 02 02 00", []byte{0x30, 0x02, 0x02, 0x00}},
			{"last bit of s flipped", func() []byte { b := bytes.Clone(good); b[len(b)-1] ^= 1; return b }()},
		}
		for _, cs := range cases {
			add(expectBad, fmt.Sprintf("ECDSA %s: %s", cv.name, cs.what), alg, k.ki, msg, cs.sig)
		}
		// An r whose top bit is set, written without the zero byte that keeps it positive: a
		// negative INTEGER to cryptobyte. Tried nonces until one gives such an r.
		for {
			r2, s2 := k.sign(e, randBelow(r, n))
			if b := r2.Bytes(); b[0]&0x80 != 0 {
				add(expectBad, fmt.Sprintf("ECDSA %s: r's top bit set and no sign byte in front", cv.name), alg, k.ki, msg,
					tlv(0x30, cat(tlv(0x02, b), derInt(s2))))
				add(expectOK, fmt.Sprintf("ECDSA %s: the same r with its sign byte", cv.name), alg, k.ki, msg, derSig(r2, s2))
				break
			}
		}

		// u1·G + u2·Q = O: r = -e/d.
		{
			rInf := new(big.Int).Mul(e, new(big.Int).ModInverse(k.d, n))
			rInf.Neg(rInf).Mod(rInf, n)
			add(expectBad, fmt.Sprintf("ECDSA %s: u1·G + u2·Q is the point at infinity", cv.name), alg, k.ki, msg, derSig(rInf, big.NewInt(12345)))
		}
		// u1·G = u2·Q, so the sum is a doubling: pick the nonce, then the key d = e/r.
		{
			nonce := randBelow(r, n)
			rx, _ := c.ScalarBaseMult(fill(nonce, (n.BitLen()+7)/8))
			rd := new(big.Int).Mod(rx, n)
			d := new(big.Int).Mul(e, new(big.Int).ModInverse(rd, n))
			d.Mod(d, n)
			kd := newEC("ecdsa-"+cv.name+"-doubling", cv.id, c, d)
			rr2, ss2 := kd.sign(e, nonce)
			add(expectOK, fmt.Sprintf("ECDSA %s: valid, and u1·G = u2·Q", cv.name), alg, kd.ki, msg, derSig(rr2, ss2))
		}
		// Q = G (d = 1), and Q = -G (d = n-1).
		for _, d := range []*big.Int{big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1))} {
			kd := newEC(fmt.Sprintf("ecdsa-%s-d%v", cv.name, d), cv.id, c, d)
			rr2, ss2 := kd.sign(e, randBelow(r, n))
			add(expectOK, fmt.Sprintf("ECDSA %s: valid under d = %s", cv.name, map[bool]string{true: "1", false: "n-1"}[d.Cmp(big.NewInt(1)) == 0]), alg, kd.ki, msg, derSig(rr2, ss2))
		}
		// Public keys that are not points (ParseCertificate would have refused them; checkSignature
		// refuses them too, in publicKeyToFIPS).
		{
			x1 := new(big.Int).Add(k.x, big.NewInt(1))
			ki := ecPubKey("ecdsa-"+cv.name+"-offcurve", cv.id, c, x1, k.y, ecPoint(c, x1, k.y))
			add(expectBad, fmt.Sprintf("ECDSA %s: public key off the curve", cv.name), alg, ki, msg, good)
			ki = ecPubKey("ecdsa-"+cv.name+"-x=p", cv.id, c, p, k.y, ecPoint(c, p, k.y))
			add(expectBad, fmt.Sprintf("ECDSA %s: public key x = p", cv.name), alg, ki, msg, good)
			if cv.id == 4 { // only P-521 leaves room for x+p in the encoding's width
				xp := new(big.Int).Add(k.x, p)
				ki = ecPubKey("ecdsa-P-521-x+p", cv.id, c, xp, k.y, ecPoint(c, xp, k.y))
				add(expectBad, "ECDSA P-521: public key with x+p for x", alg, ki, msg, good)
				yp := new(big.Int).Add(k.y, p)
				ki = ecPubKey("ecdsa-P-521-y+p", cv.id, c, k.x, yp, ecPoint(c, k.x, yp))
				add(expectBad, "ECDSA P-521: public key with y+p for y", alg, ki, msg, good)
			}
			ny := new(big.Int).Sub(p, k.y)
			ki = ecPubKey("ecdsa-"+cv.name+"-negQ", cv.id, c, k.x, ny, ecPoint(c, k.x, ny))
			add(expectBad, fmt.Sprintf("ECDSA %s: public key -Q", cv.name), alg, ki, msg, good)
		}
	}
	// Truncation for every curve and hash is covered above; the case where the digest is shorter
	// than the order (P-521 under SHA-256) is there too, and P-224 under SHA-512 truncates the most.
}

// ---- Ed25519 -----------------------------------------------------------------------------------

var (
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edL = func() *big.Int {
		v, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
		return v
	}()
	edD = func() *big.Int {
		d := new(big.Int).ModInverse(big.NewInt(121666), edP)
		d.Mul(d, big.NewInt(-121665))
		return d.Mod(d, edP)
	}()
	edI = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(1)), 2), edP)
	edB ept
	edO = ept{big.NewInt(0), big.NewInt(1)}
)

type ept struct{ x, y *big.Int }

func mod(v *big.Int) *big.Int { return v.Mod(v, edP) }

func edAdd(a, b ept) ept {
	x1y2 := new(big.Int).Mul(a.x, b.y)
	y1x2 := new(big.Int).Mul(a.y, b.x)
	y1y2 := new(big.Int).Mul(a.y, b.y)
	x1x2 := new(big.Int).Mul(a.x, b.x)
	t := mod(new(big.Int).Mul(edD, mod(new(big.Int).Mul(x1x2, y1y2))))
	xd := mod(new(big.Int).Add(big.NewInt(1), t))
	yd := mod(new(big.Int).Sub(big.NewInt(1), t))
	x := mod(new(big.Int).Mul(mod(new(big.Int).Add(x1y2, y1x2)), new(big.Int).ModInverse(xd, edP)))
	y := mod(new(big.Int).Mul(mod(new(big.Int).Add(y1y2, x1x2)), new(big.Int).ModInverse(yd, edP)))
	return ept{x, y}
}

func edNeg(a ept) ept { return ept{mod(new(big.Int).Neg(a.x)), new(big.Int).Set(a.y)} }

func edMul(k *big.Int, a ept) ept {
	r := edO
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = edAdd(r, r)
		if k.Bit(i) == 1 {
			r = edAdd(r, a)
		}
	}
	return r
}

func edEq(a, b ept) bool { return a.x.Cmp(b.x) == 0 && a.y.Cmp(b.y) == 0 }

func le(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func toLE(v *big.Int, n int) []byte {
	b := fill(v, n)
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// Decoding as edwards25519's Point.SetBytes does it: y taken modulo p, any sign bit on x = 0.
func edDecode(enc []byte) (ept, bool) {
	b := bytes.Clone(enc)
	sign := b[31] >> 7
	b[31] &= 0x7f
	y := mod(le(b))
	y2 := mod(new(big.Int).Mul(y, y))
	u := mod(new(big.Int).Sub(y2, big.NewInt(1)))
	v := mod(new(big.Int).Add(mod(new(big.Int).Mul(edD, y2)), big.NewInt(1)))
	x2 := mod(new(big.Int).Mul(u, new(big.Int).ModInverse(v, edP)))
	x := new(big.Int).Exp(x2, new(big.Int).Rsh(new(big.Int).Add(edP, big.NewInt(3)), 3), edP)
	if mod(new(big.Int).Mul(x, x)).Cmp(x2) != 0 {
		x = mod(x.Mul(x, edI))
		if mod(new(big.Int).Mul(x, x)).Cmp(x2) != 0 {
			return ept{}, false
		}
	}
	if x.Bit(0) == 1 {
		x = mod(x.Neg(x))
	}
	if sign == 1 {
		x = mod(x.Neg(x))
	}
	return ept{x, y}, true
}

func edEncode(a ept) []byte {
	b := toLE(a.y, 32)
	b[31] |= byte(a.x.Bit(0)) << 7
	return b
}

func edK(r, a, m []byte) *big.Int {
	h := sha512.Sum512(cat(r, a, m))
	return new(big.Int).Mod(le(h[:]), edL)
}

// All encodings Point.SetBytes accepts for the point a: the canonical one, y+p where that still
// fits in 255 bits, and each with the sign bit set where x = 0.
func edEncodings(a ept) [][]byte {
	var out [][]byte
	ys := []*big.Int{a.y}
	if yp := new(big.Int).Add(a.y, edP); yp.BitLen() <= 255 {
		ys = append(ys, yp)
	}
	for _, y := range ys {
		b := toLE(y, 32)
		b[31] |= byte(a.x.Bit(0)) << 7
		out = append(out, b)
		if a.x.Sign() == 0 {
			b2 := bytes.Clone(b)
			b2[31] |= 0x80
			out = append(out, b2)
		}
	}
	return out
}

func ed25519Vectors(msg []byte) {
	var ok bool
	edB, ok = edDecode([]byte{0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66})
	if !ok || !edEq(edMul(edL, edB), edO) {
		panic("the base point model is wrong")
	}
	addEd := func(label string, pub []byte) int {
		return addKey(key{name: label, kind: kEd25519, pkAlg: x509.Ed25519, pub: ed25519.PublicKey(pub), ed: pub})
	}
	alg := x509.PureEd25519
	r := stream("ed25519")

	// Real keys and Go's own signer.
	priv := ed25519.NewKeyFromSeed(randBytes(r, 32))
	pub := []byte(priv.Public().(ed25519.PublicKey))
	ki := addEd("ed25519", pub)
	for _, m := range [][]byte{msg, nil, []byte("abc"), bytes.Repeat([]byte{0x5a}, 1000)} {
		sig := ed25519.Sign(priv, m)
		// This file's model of the curve must agree with Go's before it forges anything.
		A, _ := edDecode(pub)
		R, _ := edDecode(sig[:32])
		S := le(sig[32:])
		if !edEq(edAdd(edMul(S, edB), edNeg(edMul(edK(sig[:32], pub, m), A))), R) {
			panic("the Ed25519 model disagrees with Go's signer")
		}
		add(expectOK, fmt.Sprintf("Ed25519 valid, %d-byte message", len(m)), alg, ki, m, sig)
	}
	sig := ed25519.Sign(priv, msg)
	S := le(sig[32:])
	flip := func(i int, bit byte) []byte { s := bytes.Clone(sig); s[i] ^= bit; return s }
	withS := func(v *big.Int) []byte { return cat(sig[:32], toLE(v, 32)) }
	for _, cs := range []struct {
		what string
		sig  []byte
	}{
		{"R's first bit flipped", flip(0, 1)},
		{"R's sign bit flipped", flip(31, 0x80)},
		{"S's first bit flipped", flip(32, 1)},
		{"S + l", withS(new(big.Int).Add(S, edL))},
		{"S + 2l", withS(new(big.Int).Add(S, new(big.Int).Lsh(edL, 1)))},
		{"S with bit 253 set", flip(63, 0x20)},
		{"S with bit 254 set", flip(63, 0x40)},
		{"S with bit 255 set", flip(63, 0x80)},
		{"S = l", withS(edL)},
		{"S = l-1", withS(new(big.Int).Sub(edL, big.NewInt(1)))},
		{"S = 0", withS(big.NewInt(0))},
		{"63 bytes", sig[:63]},
		{"65 bytes", cat(sig, []byte{0})},
		{"empty", nil},
		{"R non-canonical: y+p where y is R's", func() []byte {
			R, _ := edDecode(sig[:32])
			encs := edEncodings(R)
			if len(encs) > 1 {
				return cat(encs[1], sig[32:])
			}
			return flip(0, 2)
		}()},
	} {
		add(expectBad, "Ed25519: "+cs.what, alg, ki, msg, cs.sig)
	}
	add(expectBad, "Ed25519: over another message", alg, ki, []byte("another"), sig)

	// The eight points of small order, found as l·P for points P of the curve: each is a public
	// key (and an R) under every encoding SetBytes takes for it.
	var torsion []ept
	for y := int64(2); len(torsion) < 8; y++ {
		P, ok := edDecode(toLE(big.NewInt(y), 32))
		if !ok {
			continue
		}
		T := edMul(edL, P)
		seen := false
		for _, t := range torsion {
			if edEq(t, T) {
				seen = true
			}
		}
		if !seen {
			torsion = append(torsion, T)
		}
		if y > 1000 {
			panic("fewer than eight points of small order")
		}
	}
	for ti, T := range torsion {
		if !edEq(edMul(big.NewInt(8), T), edO) {
			panic("not of small order")
		}
		order := 1
		for p := T; !edEq(p, edO); p = edAdd(p, T) {
			order++
		}
		// The subgroup T generates, for the forgery below.
		var sub []ept
		for p, i := edO, 0; i < order; p, i = edAdd(p, T), i+1 {
			sub = append(sub, p)
		}
		for ei, enc := range edEncodings(T) {
			label := fmt.Sprintf("small-order A #%d (order %d), encoding %d", ti, order, ei)
			if ei > 0 {
				label += " (non-canonical)"
			}
			aki := addEd("ed25519 "+label, enc)
			A, ok := edDecode(enc)
			if !ok || !edEq(A, T) {
				panic("encoding does not decode to its point")
			}
			// Forge: R = [S]B - U for U in <A>; k = H(R || A || M); it holds when [k]A = U.
			for _, useS := range []bool{false, true} {
				found := false
				for attempt := 0; attempt < 64 && !found; attempt++ {
					m := cat(msg, []byte(fmt.Sprintf("/%d/%d/%v/%d", ti, ei, useS, attempt)))
					Sv := big.NewInt(0)
					if useS {
						Sv = randBelow(r, edL)
					}
					SB := edMul(Sv, edB)
					for _, U := range sub {
						R := edAdd(SB, edNeg(U))
						rb := edEncode(R)
						k := edK(rb, enc, m)
						if !edEq(edMul(k, A), U) {
							continue
						}
						found = true
						fsig := cat(rb, toLE(Sv, 32))
						what := fmt.Sprintf("Ed25519 forgery under %s, S %s", label, map[bool]string{false: "= 0", true: "random"}[useS])
						add(expectOK, what, alg, aki, m, fsig)
						// The same R under every other encoding SetBytes would take for it.
						for ri, renc := range edEncodings(R)[1:] {
							add(expectBad, fmt.Sprintf("%s, R re-encoded non-canonically #%d", what, ri+1), alg, aki, m, cat(renc, toLE(Sv, 32)))
						}
						break
					}
				}
				if !found {
					panic("no forgery found for " + label)
				}
			}
			add(expectBad, "Ed25519 under "+label+", a real signature by another key", alg, aki, msg, sig)
		}
	}

	// The shortest statement of where RFC 8032's decoding and Go's part: the identity as the key,
	// under each of its encodings, with R the identity and S zero — [0]B - [k]O = O whatever k is,
	// so it holds for any message, the empty one here.
	for _, enc := range edEncodings(edO) {
		aki := addEd(fmt.Sprintf("ed25519 identity %x", enc), enc)
		add(expectOK, fmt.Sprintf("Ed25519 A = %x (the identity), R = identity, S = 0, empty message", enc), alg, aki, nil,
			cat(edEncode(edO), make([]byte, 32)))
	}

	// Mixed order: A' = A + T. Cofactorless, so a signature by a holds exactly when [k]T = O.
	{
		a := randBelow(r, edL)
		A := edMul(a, edB)
		for ti, T := range torsion {
			if edEq(T, edO) {
				continue
			}
			A2 := edAdd(A, T)
			enc := edEncode(A2)
			aki := addEd(fmt.Sprintf("ed25519 mixed-order A + T#%d", ti), enc)
			for attempt := 0; attempt < 3; attempt++ {
				m := cat(msg, []byte(fmt.Sprintf("/mixed/%d/%d", ti, attempt)))
				nonce := randBelow(r, edL)
				rb := edEncode(edMul(nonce, edB))
				k := edK(rb, enc, m)
				Sv := new(big.Int).Mod(new(big.Int).Add(nonce, new(big.Int).Mul(k, a)), edL)
				add(expectAny, fmt.Sprintf("Ed25519 mixed-order key A+T#%d, attempt %d", ti, attempt), alg, aki, m, cat(rb, toLE(Sv, 32)))
			}
		}
	}

	// Public keys that are no point at all, and y values whose non-canonical form decodes.
	for y := int64(0); y < 19; y++ {
		enc := toLE(new(big.Int).Add(edP, big.NewInt(y)), 32)
		_, ok := edDecode(enc)
		aki := addEd(fmt.Sprintf("ed25519 A y=p+%d", y), enc)
		add(expectBad, fmt.Sprintf("Ed25519 A encoded as p+%d (%s), a real signature by another key", y, map[bool]string{true: "a point", false: "not a point"}[ok]), alg, aki, msg, sig)
	}
	for _, y := range []int64{2, 3, 5} {
		enc := toLE(big.NewInt(y), 32)
		if _, ok := edDecode(enc); ok {
			continue
		}
		aki := addEd(fmt.Sprintf("ed25519 A y=%d, not a point", y), enc)
		add(expectBad, fmt.Sprintf("Ed25519 A y=%d, not a point", y), alg, aki, msg, sig)
	}
}

// ---- dispatch: every algorithm against every kind of key -----------------------------------------

func algName(a x509.SignatureAlgorithm) string { return a.String() }

func dispatchVectors(msg []byte, rsaK *rsaPriv, rsaValid, rsaPSS []byte, ecKi int, ecSig []byte, edKi int, edSig []byte, mlKi [3]int, mlSig [3][]byte) {
	dsaKi := addKey(key{name: "dsa", kind: kDSA, pkAlg: x509.DSA, pub: &dsa.PublicKey{
		Parameters: dsa.Parameters{P: big.NewInt(23), Q: big.NewInt(11), G: big.NewInt(4)}, Y: big.NewInt(8)}})
	noneKi := addKey(key{name: "no key (PublicKey nil)", kind: kNone, pkAlg: x509.RSA, pub: nil})
	junk := randBytes(stream("dispatch-junk"), 64)
	type kk struct {
		name string
		ki   int
	}
	all := []kk{{"no key", noneKi}, {"RSA-2048", rsaK.ki}, {"DSA", dsaKi}, {"ECDSA P-256", ecKi}, {"Ed25519", edKi},
		{"ML-DSA-44", mlKi[0]}, {"ML-DSA-65", mlKi[1]}, {"ML-DSA-87", mlKi[2]}}
	for alg := x509.SignatureAlgorithm(-1); alg <= 22; alg++ {
		for _, k := range all {
			sig := junk
			switch {
			case k.ki == rsaK.ki && (alg == x509.SHA256WithRSA):
				sig = rsaValid
			case k.ki == rsaK.ki && (alg == x509.SHA256WithRSAPSS):
				sig = rsaPSS
			case k.ki == ecKi && alg == x509.ECDSAWithSHA256:
				sig = ecSig
			case k.ki == edKi && alg == x509.PureEd25519:
				sig = edSig
			case k.ki == mlKi[0] && alg == x509.MLDSA44:
				sig = mlSig[0]
			case k.ki == mlKi[1] && alg == x509.MLDSA65:
				sig = mlSig[1]
			case k.ki == mlKi[2] && alg == x509.MLDSA87:
				sig = mlSig[2]
			}
			add(expectAny, fmt.Sprintf("algorithm %d (%s) with %s", int(alg), algName(alg), k.name), alg, k.ki, msg, sig)
		}
	}
	for _, alg := range []x509.SignatureAlgorithm{100, 1000, -1000} {
		add(expectBad, fmt.Sprintf("algorithm %d with RSA-2048", int(alg)), alg, rsaK.ki, msg, rsaValid)
	}
}

func mldsaKeys(msg []byte) (ki [3]int, sigs [3][]byte) {
	ps := []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()}
	algs := []x509.SignatureAlgorithm{x509.MLDSA44, x509.MLDSA65, x509.MLDSA87}
	r := stream("mldsa")
	for i, p := range ps {
		sk, err := mldsa.NewPrivateKey(p, randBytes(r, 32))
		if err != nil {
			panic(err)
		}
		pk := sk.PublicKey()
		ki[i] = addKey(key{name: "mldsa " + p.String(), kind: kMLDSA, pkAlg: x509.MLDSA, pub: pk, ml: i + 1, mpk: pk.Bytes()})
		sigs[i], err = sk.SignDeterministic(msg, nil)
		if err != nil {
			panic(err)
		}
		add(expectOK, p.String()+" valid", algs[i], ki[i], msg, sigs[i])
		bad := bytes.Clone(sigs[i])
		bad[10] ^= 1
		add(expectBad, p.String()+" flipped bit", algs[i], ki[i], msg, bad)
		add(expectBad, p.String()+" one byte short", algs[i], ki[i], msg, sigs[i][1:])
		add(expectBad, p.String()+" over another message", algs[i], ki[i], []byte("another"), sigs[i])
		add(expectBad, p.String()+" empty", algs[i], ki[i], msg, nil)
	}
	return
}

// ---- the header ----------------------------------------------------------------------------------

type pool struct {
	b   []byte
	idx map[string]int
}

func (p *pool) put(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	if o, ok := p.idx[string(b)]; ok {
		return o, len(b)
	}
	o := len(p.b)
	p.b = append(p.b, b...)
	p.idx[string(b)] = o
	return o, len(b)
}

func cstr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range []byte(s) {
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(&b, "\\%03o", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func main() {
	if runtime.Version() != "go1.27.3" {
		fmt.Fprintln(os.Stderr, "tools/sigvec: this must run under go1.27.3, the REALITY reference's toolchain; this is", runtime.Version())
		os.Exit(1)
	}
	r := stream("messages")
	msg := randBytes(r, 300)
	other := randBytes(r, 300)

	rsaVectors(msg, other)
	ecdsaVectors(msg, other)
	ed25519Vectors(msg)
	mlKi, mlSig := mldsaKeys(msg)

	// The keys dispatchVectors pairs with each algorithm: the first of each kind made above.
	var rsaK *rsaPriv
	var ecKi, edKi = -1, -1
	for i, k := range keys {
		if k.name == "rsa2048-e65537" && rsaK == nil {
			rsaK = &rsaPriv{ki: i}
		}
		if k.name == "ecdsa-P-256" {
			ecKi = i
		}
		if k.name == "ed25519" {
			edKi = i
		}
	}
	find := func(what string) []byte {
		for _, v := range vecs {
			if v.what == what {
				return v.sig
			}
		}
		panic("no vector " + what)
	}
	dispatchVectors(msg, rsaK,
		find("RSA-2048 e=65537 SHA-256 PKCS#1 v1.5 valid"), find("RSA-2048 e=65537 SHA-256 PSS valid"),
		ecKi, find("ECDSA P-256 SHA-256 valid"), edKi, find(fmt.Sprintf("Ed25519 valid, %d-byte message", len(msg))), mlKi, mlSig)

	p := &pool{idx: map[string]int{}}
	var out strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&out, f, a...) }
	w("/* Generated by tools/sigvec from Go's own x509 checkSignature (go1.27.1), reached through\n")
	w(" * Certificate.CheckSignatureFrom; see its header for how to regenerate. Do not edit. */\n")
	w("#ifndef LC_GOSIG_REFERENCE_H\n#define LC_GOSIG_REFERENCE_H\n\n#include <stddef.h>\n#include <stdint.h>\n\n")
	w("typedef struct {\n    const char *name;\n    int         kind, n_nil;\n    uint32_t    n_off, n_len;\n    int64_t     e;\n")
	w("    int         curve;\n    uint32_t    pt_off, pt_len, ed_off;\n    int         ml;\n    uint32_t    mpk_off, mpk_len;\n} sv_key;\n\n")
	w("typedef struct {\n    const char *what;\n    int         alg, key;\n    uint32_t    msg_off, msg_len, sig_off, sig_len;\n")
	w("    const char *want; /* \"\" = nil */\n    int         ml_reach;\n    const char *ml_inner;\n} sv_vec;\n\n")

	var kl, vl strings.Builder
	for _, k := range keys {
		no, nl := p.put(k.n)
		po, pl := p.put(k.point)
		eo, _ := p.put(k.ed)
		mo, ml := p.put(k.mpk)
		nn := 0
		if k.nNil {
			nn = 1
		}
		fmt.Fprintf(&kl, "    { %s, %d, %d, %d, %d, INT64_C(%d), %d, %d, %d, %d, %d, %d, %d },\n",
			cstr(k.name), k.kind, nn, no, nl, k.e, k.curve, po, pl, eo, k.ml, mo, ml)
	}
	counts := map[bool]int{}
	for _, v := range vecs {
		mo, ml := p.put(v.msg)
		so, sl := p.put(v.sig)
		reach := 0
		if v.mlReach {
			reach = 1
		}
		counts[v.want == ""]++
		fmt.Fprintf(&vl, "    { %s, %d, %d, %d, %d, %d, %d, %s, %d, %s },\n",
			cstr(v.what), int(v.alg), v.key, mo, ml, so, sl, cstr(v.want), reach, cstr(v.mlInner))
	}
	w("static const uint8_t sv_pool[] = {")
	for i, c := range p.b {
		if i%24 == 0 {
			w("\n   ")
		}
		w(" %d,", c)
	}
	w("\n};\n\n")
	w("static const sv_key sv_keys[] = {\n%s};\n\n", kl.String())
	// SignatureAlgorithm.String() and PublicKeyAlgorithm.String(), from -1 up.
	w("static const char *const sv_alg_names[] = {")
	for a := -1; a <= 22; a++ {
		w(" %s,", cstr(x509.SignatureAlgorithm(a).String()))
	}
	w(" };\nstatic const char *const sv_pk_names[] = {")
	for a := -1; a <= 7; a++ {
		w(" %s,", cstr(x509.PublicKeyAlgorithm(a).String()))
	}
	w(" };\n\n")
	w("/* %d vectors: %d that Go accepts, %d it refuses. */\n", len(vecs), counts[true], counts[false])
	w("static const sv_vec sv_vecs[] = {\n%s};\n\n#endif\n", vl.String())
	os.Stdout.WriteString(out.String())
	fmt.Fprintf(os.Stderr, "%d keys, %d vectors (%d accepted, %d refused), pool %d bytes\n", len(keys), len(vecs), counts[true], counts[false], len(p.b))
}
