// What Go 1.27.1 says of an ML-DSA key and signature — crypto/mldsa's own NewPublicKey and
// Verify(pub, msg, sig, nil), as crypto/x509 calls them (GOROOT/src/crypto/x509/parser.go:366-374,
// GOROOT/src/crypto/x509/x509.go:1115-1138). Writes test/mldsa/reference.h, which test/mldsa holds
// lc_mldsa_public_key_ok and lc_mldsa_verify (cert/mldsa.c) to, verdict for verdict and error
// text for error text.
//
// THE KEYS come from fixed seeds (mldsa.NewPrivateKey) and the signatures from SignDeterministic,
// so every run writes the same header. Each valid (key, message, signature) is a base, and each
// base is then mutated: a bit flipped in every byte of the signature, a byte of the hint region set
// to 0x00 and to 0xff, bits flipped across the key and the message, all three cut and extended, the
// parameter set swapped. Random mutation seldom reaches a rule that needs a well-formed value of a
// particular shape, so those are written out one by one as bases of their own (crafted): each of
// hintDecode's refusals, a hint layout that decodes and is still wrong, z out of range alone and
// together with a bad hint, and signatures of every length.
//
// THE FORGER. Whether ||z||∞ ≥ γ1 − β is checked with ≥ or with > shows only on a signature whose
// challenge is right and whose z reaches γ1 − β exactly, and no honest signer makes one. So this
// file carries its own ML-DSA signer (FIPS 204 over plain integers, forge*), with the rejection
// rules as a parameter: it makes signatures with z at γ1 − β − 1 (valid), at γ1 − β (valid but for
// the bound), and signatures the signer's r0/ct0 rules would have rejected, which the verifier does
// not look at. It is checked against Go before it is used: its key must be Go's key and, with
// Go's rules and zero randomness, its signature must be SignDeterministic's, byte for byte. What
// Go's Verify then says of each is what is written down — the forger only reaches the input.
// A second forger (forgeZeroT1) puts any hints at all in front of the verifier; see there.
//
// Not built by the gate. Regenerate in the build image, from the repository root:
//
//	docker run --rm -v "$PWD:/w" -w /w lc-build:local sh -c 'cd tools/mldsavec && \
//	  /usr/local/go1.27/bin/go run . > ../../test/mldsa/reference.h'
package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha3"
	"fmt"
	"os"
	"strings"
)

// ---- parameter sets, as the C side numbers them --------------------------------------------------

// 1, 2, 3 are LC_MLDSA_44, _65, _87 (cert/mldsa.h); 0 is Go's zero mldsa.Parameters{}.
func goParams(c int) mldsa.Parameters {
	switch c {
	case 1:
		return mldsa.MLDSA44()
	case 2:
		return mldsa.MLDSA65()
	case 3:
		return mldsa.MLDSA87()
	}
	return mldsa.Parameters{}
}

type fparams struct {
	k, l, eta, gamma1, gamma2, lambda, tau, omega int
}

// GOROOT/src/crypto/internal/fips140/mldsa/mldsa.go:27-31.
var fp = map[int]fparams{
	1: {4, 4, 2, 17, 88, 128, 39, 80},
	2: {6, 5, 4, 19, 32, 192, 49, 55},
	3: {8, 7, 2, 19, 32, 256, 60, 75},
}

func sigSize(p fparams) int { return p.lambda/4 + p.l*256*(p.gamma1+1)/8 + p.omega + p.k }

// ---- the forger: FIPS 204 over plain integers mod q ----------------------------------------------

const q = 8380417
const n = 256

type poly [n]int64

var zetas [256]int64

func init() {
	for k := 0; k < 256; k++ {
		br := 0
		for b := 0; b < 8; b++ {
			br |= (k >> b & 1) << (7 - b)
		}
		z := int64(1)
		for i := 0; i < br; i++ {
			z = z * 1753 % q
		}
		zetas[k] = z
	}
}

// FIPS 204 Algorithm 41.
func nttP(w poly) poly {
	m := 0
	for ln := 128; ln >= 1; ln /= 2 {
		for start := 0; start < 256; start += 2 * ln {
			m++
			z := zetas[m]
			for j := start; j < start+ln; j++ {
				t := z * w[j+ln] % q
				w[j+ln] = (w[j] - t + q) % q
				w[j] = (w[j] + t) % q
			}
		}
	}
	return w
}

// FIPS 204 Algorithm 42.
func invNTTP(w poly) poly {
	m := 256
	for ln := 1; ln < 256; ln *= 2 {
		for start := 0; start < 256; start += 2 * ln {
			m--
			z := q - zetas[m]
			for j := start; j < start+ln; j++ {
				t := w[j]
				w[j] = (t + w[j+ln]) % q
				w[j+ln] = (t - w[j+ln] + q) % q
				w[j+ln] = z * w[j+ln] % q
			}
		}
	}
	for j := range w {
		w[j] = w[j] * 8347681 % q
	}
	return w
}

func mulP(a, b poly) (c poly) {
	for i := range c {
		c[i] = a[i] * b[i] % q
	}
	return
}

func addP(a, b poly) (c poly) {
	for i := range c {
		c[i] = (a[i] + b[i]) % q
	}
	return
}

func subP(a, b poly) (c poly) {
	for i := range c {
		c[i] = (a[i] - b[i] + q) % q
	}
	return
}

func norm(v int64) int64 {
	if v > q/2 {
		return q - v
	}
	return v
}

func shake256(length int, parts ...[]byte) []byte {
	h := sha3.NewSHAKE256()
	for _, p := range parts {
		h.Write(p)
	}
	out := make([]byte, length)
	h.Read(out)
	return out
}

func sampleNTTP(rho []byte, s, r byte) (a poly) {
	g := sha3.NewSHAKE128()
	g.Write(rho)
	g.Write([]byte{s, r})
	b := make([]byte, 3)
	for j := 0; j < n; {
		g.Read(b)
		v := int64(b[0]) | int64(b[1])<<8 | int64(b[2]&0x7f)<<16
		if v < q {
			a[j] = v
			j++
		}
	}
	return
}

func sampleBoundedP(rho []byte, r byte, eta int) (a poly) {
	h := sha3.NewSHAKE256()
	h.Write(rho)
	h.Write([]byte{r, 0})
	b := make([]byte, 1)
	put := func(j *int, z int64) {
		if *j >= n {
			return
		}
		if eta == 2 && z < 15 {
			a[*j] = (2 - z%5 + q) % q
			*j++
		} else if eta == 4 && z < 9 {
			a[*j] = (4 - z + q) % q
			*j++
		}
	}
	for j := 0; j < n; {
		h.Read(b)
		put(&j, int64(b[0]&0x0f))
		put(&j, int64(b[0]>>4))
	}
	return
}

func sampleInBallP(ch []byte, tau int) (c poly) {
	h := sha3.NewSHAKE256()
	h.Write(ch)
	s := make([]byte, 8)
	h.Read(s)
	b := make([]byte, 1)
	for i := 256 - tau; i < 256; i++ {
		h.Read(b)
		for int(b[0]) > i {
			h.Read(b)
		}
		j := int(b[0])
		c[i] = c[j]
		bit := i + tau - 256
		if s[bit/8]>>(bit%8)&1 == 0 {
			c[j] = 1
		} else {
			c[j] = q - 1
		}
	}
	return
}

// FIPS 204 Algorithm 36.
func decompose(r int64, gamma2 int64) (r1, r0 int64) {
	r0 = r % (2 * gamma2)
	if r0 > gamma2 {
		r0 -= 2 * gamma2
	}
	if r-r0 == q-1 {
		return 0, r0 - 1
	}
	return (r - r0) / (2 * gamma2), r0
}

// Little-endian packing of `bits`-bit values.
func pack(vals []int64, bits int) []byte {
	out := make([]byte, len(vals)*bits/8)
	pos := 0
	for _, v := range vals {
		for b := 0; b < bits; b++ {
			if v>>b&1 == 1 {
				out[pos/8] |= 1 << (pos % 8)
			}
			pos++
		}
	}
	return out
}

func unpack(buf []byte, bits int) []int64 {
	vals := make([]int64, len(buf)*8/bits)
	for i := range vals {
		for b := 0; b < bits; b++ {
			pos := i*bits + b
			vals[i] |= int64(buf[pos/8]>>(pos%8)&1) << b
		}
	}
	return vals
}

type forgeKey struct {
	c          int
	p          fparams
	a          [][]poly // NTT domain, a[r][s]
	s1, s2, t0 []poly
	pk, tr, kk []byte
}

func forgeKeyGen(c int, seed []byte) *forgeKey {
	p := fp[c]
	fk := &forgeKey{c: c, p: p}
	x := shake256(128, seed, []byte{byte(p.k), byte(p.l)})
	rho, rhoS := x[:32], x[32:96]
	fk.kk = x[96:128]
	fk.a = make([][]poly, p.k)
	for r := 0; r < p.k; r++ {
		fk.a[r] = make([]poly, p.l)
		for s := 0; s < p.l; s++ {
			fk.a[r][s] = sampleNTTP(rho, byte(s), byte(r))
		}
	}
	for r := 0; r < p.l; r++ {
		fk.s1 = append(fk.s1, sampleBoundedP(rhoS, byte(r), p.eta))
	}
	for r := 0; r < p.k; r++ {
		fk.s2 = append(fk.s2, sampleBoundedP(rhoS, byte(p.l+r), p.eta))
	}
	pk := append([]byte{}, rho...)
	for i := 0; i < p.k; i++ {
		var acc poly
		for j := 0; j < p.l; j++ {
			acc = addP(acc, mulP(fk.a[i][j], nttP(fk.s1[j])))
		}
		t := addP(invNTTP(acc), fk.s2[i])
		var t0 poly
		t1 := make([]int64, n)
		for j := range t {
			t1[j] = (t[j] + 1<<12 - 1) >> 13
			t0[j] = (t[j] - t1[j]<<13 + q) % q
		}
		fk.t0 = append(fk.t0, t0)
		pk = append(pk, pack(t1, 10)...)
	}
	fk.pk = pk
	fk.tr = shake256(64, pk)
	return fk
}

// What the signer's rejection rules saw of one attempt.
type attempt struct {
	zmax      int64
	r0Fail    bool
	ct0Fail   bool
	hintCount int
}

func forgeSign(fk *forgeKey, msg []byte, accept func(attempt) bool, maxTries int) []byte {
	p := fk.p
	beta := int64(p.tau * p.eta)
	g1 := int64(1) << p.gamma1
	g2 := int64((q - 1) / p.gamma2)
	mu := shake256(64, fk.tr, []byte{0, 0}, msg)
	rhoPP := shake256(64, fk.kk, make([]byte, 32), mu)
	zlen := (p.gamma1 + 1) * n / 8
	kappa := 0
	for try := 0; try < maxTries; try++ {
		y := make([]poly, p.l)
		yHat := make([]poly, p.l)
		for r := range y {
			v := unpack(shake256(zlen, rhoPP, []byte{byte(kappa), byte(kappa >> 8)}), p.gamma1+1)
			kappa++
			for j := range v {
				y[r][j] = ((g1-v[j])%q + q) % q
			}
			yHat[r] = nttP(y[r])
		}
		w := make([]poly, p.k)
		var w1enc []byte
		for i := range w {
			var acc poly
			for j := 0; j < p.l; j++ {
				acc = addP(acc, mulP(fk.a[i][j], yHat[j]))
			}
			w[i] = invNTTP(acc)
			hb := make([]int64, n)
			for j := range hb {
				hb[j], _ = decompose(w[i][j], g2)
			}
			if p.gamma2 == 32 {
				w1enc = append(w1enc, pack(hb, 4)...)
			} else {
				w1enc = append(w1enc, pack(hb, 6)...)
			}
		}
		ch := shake256(p.lambda/4, mu, w1enc)
		cHat := nttP(sampleInBallP(ch, p.tau))
		var at attempt
		z := make([]poly, p.l)
		for i := range z {
			z[i] = addP(y[i], invNTTP(mulP(cHat, nttP(fk.s1[i]))))
			for _, v := range z[i] {
				if norm(v) > at.zmax {
					at.zmax = norm(v)
				}
			}
		}
		if at.zmax > g1-beta {
			continue // cannot be encoded as the bound under test anyway past γ1 − β
		}
		hints := make([][]int, p.k)
		for i := range w {
			cs2 := invNTTP(mulP(cHat, nttP(fk.s2[i])))
			ct0 := invNTTP(mulP(cHat, nttP(fk.t0[i])))
			r := subP(w[i], cs2)
			for j := 0; j < n; j++ {
				_, r0 := decompose(r[j], g2)
				if r0 < 0 {
					r0 = -r0
				}
				if r0 >= g2-beta {
					at.r0Fail = true
				}
				if norm(ct0[j]) >= g2 {
					at.ct0Fail = true
				}
				v1, _ := decompose(r[j], g2)
				r1, _ := decompose((r[j]+ct0[j])%q, g2)
				if v1 != r1 {
					hints[i] = append(hints[i], j)
					at.hintCount++
				}
			}
		}
		if !accept(at) || at.hintCount > p.omega {
			continue
		}
		sig := append([]byte{}, ch...)
		for i := range z {
			v := make([]int64, n)
			for j := range v {
				zc := z[i][j]
				if zc > q/2 {
					zc -= q
				}
				v[j] = g1 - zc
			}
			sig = append(sig, pack(v, p.gamma1+1)...)
		}
		y2 := make([]byte, p.omega+p.k)
		idx := 0
		for i := range hints {
			for _, j := range hints[i] {
				y2[idx] = byte(j)
				idx++
			}
			y2[p.omega+i] = byte(idx)
		}
		return append(sig, y2...)
	}
	return nil
}

// ---- the second forger: a key whose t1 is zero ----------------------------------------------------
//
// With t1 = 0 the verifier's w' = A·z − c·t1·2^d is A·z: it does not depend on the challenge, so
// any z and ANY hints can be given the c~ that makes them a valid signature — c~ = H(μ ||
// w1Encode(UseHint(h, A·z))). NewPublicKey takes such a key like any other. This is how the rules
// no honest signature reaches are put in front of the verifier: a hint where LowBits is exactly 0
// (UseHint's r0 > 0), hints where r1 wraps around m, exactly ω hints, z at the bound.

func useHintP(h bool, r1, r0 int64, gamma2 int) int64 {
	m := int64((q - 1) / (2 * ((q - 1) / gamma2)))
	if !h {
		return r1
	}
	if r0 > 0 {
		return (r1 + 1) % m
	}
	return (r1 - 1 + m) % m
}

// pickHints gets r1 and r0 of every coefficient of w' and returns the hinted positions of each
// polynomial in rising order, or nil to ask for another z.
func forgeZeroT1(c int, rho, msg []byte, fixZ func(z [][]int64), pickHints func(r1, r0 [][]int64) [][]int) (pk, sig []byte) {
	p := fp[c]
	g1 := int64(1) << p.gamma1
	bound := g1 - int64(p.tau*p.eta) - 1 // the largest |z| a valid signature has
	g2 := int64((q - 1) / p.gamma2)
	pk = append(append([]byte{}, rho...), make([]byte, p.k*320)...)
	tr := shake256(64, pk)
	mu := shake256(64, tr, []byte{0, 0}, msg)
	a := make([][]poly, p.k)
	for r := range a {
		a[r] = make([]poly, p.l)
		for s := range a[r] {
			a[r][s] = sampleNTTP(rho, byte(s), byte(r))
		}
	}
	for ctr := 0; ctr < 100000; ctr++ {
		rnd := shake256(4*n*p.l, []byte("z"), msg, []byte{byte(ctr), byte(ctr >> 8), byte(ctr >> 16)})
		z := make([][]int64, p.l)
		for i := range z {
			z[i] = make([]int64, n)
			for j := range z[i] {
				o := 4 * (i*n + j)
				v := int64(rnd[o]) | int64(rnd[o+1])<<8 | int64(rnd[o+2])<<16 | int64(rnd[o+3])<<24
				z[i][j] = v%(2*bound+1) - bound
			}
		}
		if fixZ != nil {
			fixZ(z)
		}
		zHat := make([]poly, p.l)
		for i := range z {
			var zp poly
			for j := range zp {
				zp[j] = (z[i][j] + q) % q
			}
			zHat[i] = nttP(zp)
		}
		r1 := make([][]int64, p.k)
		r0 := make([][]int64, p.k)
		for i := 0; i < p.k; i++ {
			var acc poly
			for j := 0; j < p.l; j++ {
				acc = addP(acc, mulP(a[i][j], zHat[j]))
			}
			w := invNTTP(acc)
			r1[i], r0[i] = make([]int64, n), make([]int64, n)
			for j := range w {
				r1[i][j], r0[i][j] = decompose(w[j], g2)
			}
		}
		hints := pickHints(r1, r0)
		if hints == nil {
			continue
		}
		var w1enc []byte
		for i := 0; i < p.k; i++ {
			hinted := map[int]bool{}
			for _, j := range hints[i] {
				hinted[j] = true
			}
			w1 := make([]int64, n)
			for j := range w1 {
				w1[j] = useHintP(hinted[j], r1[i][j], r0[i][j], p.gamma2)
			}
			if p.gamma2 == 32 {
				w1enc = append(w1enc, pack(w1, 4)...)
			} else {
				w1enc = append(w1enc, pack(w1, 6)...)
			}
		}
		sig = shake256(p.lambda/4, mu, w1enc)
		for i := range z {
			v := make([]int64, n)
			for j := range v {
				v[j] = g1 - z[i][j]
			}
			sig = append(sig, pack(v, p.gamma1+1)...)
		}
		y := make([]byte, p.omega+p.k)
		idx := 0
		for i := range hints {
			for _, j := range hints[i] {
				y[idx] = byte(j)
				idx++
			}
			y[p.omega+i] = byte(idx)
		}
		return pk, append(sig, y...)
	}
	return nil, nil
}

// ---- cases ---------------------------------------------------------------------------------------

type base struct {
	what         string
	params       int
	pk, msg, sig []byte
}

// target: 0 nothing, 1 the key, 2 the message, 3 the signature.
// op: 0 none, 1 xor val at pos, 2 set val at pos, 3 cut to pos bytes, 4 append pos bytes of val.
type mutation struct {
	base   int
	params int // the parameter set the call is made with
	target byte
	op     byte
	pos    int
	val    byte
}

func apply(b []byte, t byte, m mutation) []byte {
	out := append([]byte{}, b...)
	if m.target != t {
		return out
	}
	switch m.op {
	case 1:
		out[m.pos] ^= m.val
	case 2:
		out[m.pos] = m.val
	case 3:
		out = out[:m.pos]
	case 4:
		out = append(out, bytes.Repeat([]byte{m.val}, m.pos)...)
	}
	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// NewPublicKey's answer, and Verify's — which, without a key, is NewPublicKey's refusal.
func verdict(bs []base, m mutation) (string, string) {
	b := bs[m.base]
	pk, msg, sig := apply(b.pk, 1, m), apply(b.msg, 2, m), apply(b.sig, 3, m)
	pub, err := mldsa.NewPublicKey(goParams(m.params), pk)
	if err != nil {
		return err.Error(), err.Error()
	}
	return "", errText(mldsa.Verify(pub, msg, sig, nil))
}

func seedFor(c, i int) []byte {
	s := make([]byte, 32)
	for j := range s {
		s[j] = byte(c*97 + i*31 + j*7 + 1)
	}
	return s
}

func message(length, salt int) []byte {
	m := make([]byte, length)
	for i := range m {
		m[i] = byte(i*13 + salt*5 + 3)
	}
	return m
}

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}

func main() {
	var bs []base
	var ms []mutation
	add := func(b base) int {
		bs = append(bs, b)
		return len(bs) - 1
	}
	none := func(bi int) { ms = append(ms, mutation{base: bi, params: bs[bi].params}) }

	// Message lengths around SHAKE256's rate: tr and two bytes come first, so 70 fills the first
	// 136-byte block exactly and 206 the second.
	lengths := []int{0, 1, 69, 70, 71, 136, 137, 206, 1000}

	for c := 1; c <= 3; c++ {
		p := fp[c]
		var sks []*mldsa.PrivateKey
		for i := 0; i < 2; i++ {
			sk, err := mldsa.NewPrivateKey(goParams(c), seedFor(c, i))
			if err != nil {
				die("NewPrivateKey: %v", err)
			}
			sks = append(sks, sk)
		}
		sign := func(sk *mldsa.PrivateKey, msg []byte) []byte {
			sig, err := sk.SignDeterministic(msg, nil)
			if err != nil {
				die("SignDeterministic: %v", err)
			}
			return sig
		}
		pk0 := sks[0].PublicKey().Bytes()
		pk1 := sks[1].PublicKey().Bytes()

		// The forger first proves it signs as Go does.
		fk := forgeKeyGen(c, seedFor(c, 0))
		if !bytes.Equal(fk.pk, pk0) {
			die("forger: %s key differs from Go's", goParams(c))
		}
		msg70 := message(70, c)
		honest := func(a attempt) bool {
			return a.zmax < int64(1)<<p.gamma1-int64(p.tau*p.eta) && !a.r0Fail && !a.ct0Fail
		}
		if !bytes.Equal(forgeSign(fk, msg70, honest, 1000), sign(sks[0], msg70)) {
			die("forger: %s signature differs from SignDeterministic", goParams(c))
		}

		// Valid signatures over every length, by the first key; a few by the second.
		first, start := -1, len(bs)
		for _, ln := range lengths {
			msg := message(ln, c)
			bi := add(base{fmt.Sprintf("%s, key 0, %d-byte message", goParams(c), ln), c, pk0, msg, sign(sks[0], msg)})
			none(bi)
			if ln == 70 {
				first = bi
			}
		}
		for _, ln := range []int{0, 70, 137} {
			msg := message(ln, c+7)
			none(add(base{fmt.Sprintf("%s, key 1, %d-byte message", goParams(c), ln), c, pk1, msg, sign(sks[1], msg)}))
		}
		// Key 0's signature under key 1.
		none(add(base{fmt.Sprintf("%s, key 0's signature checked with key 1", goParams(c)), c, pk1, msg70, sign(sks[0], msg70)}))
		// Keys Go takes although no key generation makes them.
		none(add(base{fmt.Sprintf("%s, an all-zero key", goParams(c)), c, make([]byte, len(pk0)), msg70, sign(sks[0], msg70)}))
		none(add(base{fmt.Sprintf("%s, an all-0xff key", goParams(c)), c, bytes.Repeat([]byte{0xff}, len(pk0)), msg70, sign(sks[0], msg70)}))

		b0 := bs[first]
		sl := len(b0.sig)
		hintOff := sl - p.omega - p.k

		// The signature: a bit flipped in every byte; every byte of the hints set to 0 and 0xff.
		for pos := 0; pos < sl; pos++ {
			ms = append(ms, mutation{first, c, 3, 1, pos, byte(1 << (pos % 8))})
		}
		for pos := hintOff; pos < sl; pos++ {
			ms = append(ms, mutation{first, c, 3, 2, pos, 0x00}, mutation{first, c, 3, 2, pos, 0xff})
		}
		// Cut and extended, including to every other parameter set's length.
		for _, cut := range []int{0, 1, p.lambda / 4, sl - 1} {
			ms = append(ms, mutation{first, c, 3, 3, cut, 0})
		}
		ms = append(ms, mutation{first, c, 3, 4, 1, 0}, mutation{first, c, 3, 4, 1, 0xff})
		for o := 1; o <= 3; o++ {
			if o == c {
				continue
			}
			if other := sigSize(fp[o]); other < sl {
				ms = append(ms, mutation{first, c, 3, 3, other, 0})
			} else {
				ms = append(ms, mutation{first, c, 3, 4, other - sl, 0})
			}
		}
		// The key: every byte of ρ, then every seventh; cut and extended.
		pl := len(pk0)
		for pos := 0; pos < pl; pos++ {
			if pos < 32 || pos%7 == 0 || pos == pl-1 {
				ms = append(ms, mutation{first, c, 1, 1, pos, byte(0x80 >> (pos % 8))})
			}
		}
		for _, cut := range []int{0, 1, 32, pl - 1} {
			ms = append(ms, mutation{first, c, 1, 3, cut, 0})
		}
		ms = append(ms, mutation{first, c, 1, 4, 1, 0})
		for o := 1; o <= 3; o++ {
			if o == c {
				continue
			}
			if other := 32 + fp[o].k*320; other < pl {
				ms = append(ms, mutation{first, c, 1, 3, other, 0})
			} else {
				ms = append(ms, mutation{first, c, 1, 4, other - pl, 0})
			}
		}
		// The message: every byte, cut, extended.
		for pos := 0; pos < len(b0.msg); pos++ {
			ms = append(ms, mutation{first, c, 2, 1, pos, byte(1 << (pos % 8))})
		}
		ms = append(ms, mutation{first, c, 2, 3, 0, 0}, mutation{first, c, 2, 3, 69, 0},
			mutation{first, c, 2, 4, 1, 0}, mutation{first, c, 2, 4, 67, 0x5a})
		// The wrong parameter set, and none at all.
		for o := 0; o <= 3; o++ {
			if o != c {
				ms = append(ms, mutation{base: first, params: o})
			}
		}
		// A few flips on every other base.
		for bi := start; bi < len(bs); bi++ {
			if bi == first || bs[bi].params != c {
				continue
			}
			l := len(bs[bi].sig)
			ms = append(ms, mutation{bi, c, 3, 1, 0, 1}, mutation{bi, c, 3, 1, l - 1, 0x80},
				mutation{bi, c, 3, 1, p.lambda/4 + 5, 0x10})
			if len(bs[bi].msg) > 0 {
				ms = append(ms, mutation{bi, c, 2, 1, len(bs[bi].msg) - 1, 0x01})
			}
		}

		// ---- crafted, one rule at a time ----
		crafted := func(what string, edit func(s []byte) bool) {
			s := append([]byte{}, b0.sig...)
			if !edit(s) {
				fmt.Fprintf(os.Stderr, "%s: %s: not applicable to this signature, skipped\n", goParams(c), what)
				return
			}
			none(add(base{fmt.Sprintf("%s, %s", goParams(c), what), c, pk0, msg70, s}))
		}
		y := func(s []byte) []byte { return s[hintOff:] }
		lim := func(s []byte, i int) int { return int(y(s)[p.omega+i]) }
		setZ := func(s []byte, poly, coeff int, chunk uint32) {
			// Write one (γ1+1)-bit chunk of z, little-endian, leaving the others as they are.
			bits := p.gamma1 + 1
			start := p.lambda/4*8 + (poly*256+coeff)*bits
			for b := 0; b < bits; b++ {
				pos := start + b
				s[pos/8] &^= 1 << (pos % 8)
				s[pos/8] |= byte(chunk>>b&1) << (pos % 8)
			}
		}
		g1 := uint32(1) << p.gamma1
		g1b := g1 - uint32(p.tau*p.eta)

		crafted("hint limits decreasing", func(s []byte) bool {
			for i := 1; i < p.k; i++ {
				if lim(s, i-1) > 0 {
					y(s)[p.omega+i] = byte(lim(s, i-1) - 1)
					return true
				}
			}
			return false
		})
		crafted("hint limit past ω", func(s []byte) bool {
			y(s)[p.omega+p.k-1] = byte(p.omega + 1)
			return true
		})
		crafted("hint limit 255", func(s []byte) bool {
			y(s)[p.omega] = 255
			return true
		})
		crafted("hint limit exactly ω, indices rising", func(s []byte) bool {
			start := 0
			if p.k > 1 {
				start = lim(s, p.k-2)
			}
			for j := start; j < p.omega; j++ {
				y(s)[j] = byte(j - start)
			}
			y(s)[p.omega+p.k-1] = byte(p.omega)
			return true
		})
		crafted("hint limit exactly ω, indices up to 255", func(s []byte) bool {
			start := 0
			if p.k > 1 {
				start = lim(s, p.k-2)
			}
			for j := start; j < p.omega; j++ {
				y(s)[j] = byte(255 - (p.omega - 1 - j))
			}
			y(s)[p.omega+p.k-1] = byte(p.omega)
			return true
		})
		inPoly := func(s []byte, edit func(s []byte, a int)) bool {
			prev := 0
			for i := 0; i < p.k; i++ {
				if lim(s, i)-prev >= 2 {
					edit(s, prev)
					return true
				}
				prev = lim(s, i)
			}
			return false
		}
		crafted("hint index repeated", func(s []byte) bool {
			return inPoly(s, func(s []byte, a int) { y(s)[a+1] = y(s)[a] })
		})
		crafted("hint indices falling", func(s []byte) bool {
			return inPoly(s, func(s []byte, a int) { y(s)[a], y(s)[a+1] = y(s)[a+1], y(s)[a] })
		})
		crafted("hint index falling at the end of a polynomial", func(s []byte) bool {
			prev := 0
			for i := 0; i < p.k; i++ {
				if lim(s, i)-prev >= 2 {
					e := lim(s, i) - 1
					y(s)[e] = y(s)[e-1] - 1
					if y(s)[e-1] == 0 {
						y(s)[e] = 0
					}
					return true
				}
				prev = lim(s, i)
			}
			return false
		})
		crafted("hint extra index after the last limit", func(s []byte) bool {
			total := lim(s, p.k-1)
			if total >= p.omega {
				return false
			}
			y(s)[total] = 1
			return true
		})
		crafted("hint extra index in the last padding byte", func(s []byte) bool {
			if lim(s, p.k-1) >= p.omega {
				return false
			}
			y(s)[p.omega-1] = 0x80
			return true
		})
		crafted("hint last index of polynomial 0 moved to polynomial 1", func(s []byte) bool {
			if lim(s, 0) == 0 {
				return false
			}
			y(s)[p.omega] = byte(lim(s, 0) - 1)
			return true
		})
		crafted("hint first index of polynomial 1 moved to polynomial 0", func(s []byte) bool {
			if lim(s, 1) == lim(s, 0) {
				return false
			}
			y(s)[p.omega] = byte(lim(s, 0) + 1)
			return true
		})
		crafted("no hints at all", func(s []byte) bool {
			for j := range y(s) {
				y(s)[j] = 0
			}
			return true
		})
		crafted("every hint in the last polynomial", func(s []byte) bool {
			total := lim(s, p.k-1)
			for i := 0; i < p.k-1; i++ {
				y(s)[p.omega+i] = 0
			}
			for j := 0; j < total; j++ {
				y(s)[j] = byte(j * 3)
			}
			return true
		})
		crafted("z = γ1 in the first coefficient", func(s []byte) bool {
			setZ(s, 0, 0, 0)
			return true
		})
		crafted("z = −γ1+1 in the last coefficient", func(s []byte) bool {
			setZ(s, p.l-1, 255, 2*g1-1)
			return true
		})
		crafted("z = γ1 − β in a middle coefficient", func(s []byte) bool {
			setZ(s, p.l/2, 100, g1-g1b)
			return true
		})
		crafted("z = −(γ1 − β) in a middle coefficient", func(s []byte) bool {
			setZ(s, p.l/2, 101, g1+g1b)
			return true
		})
		crafted("z = γ1 − β − 1 in a middle coefficient", func(s []byte) bool {
			setZ(s, p.l/2, 102, g1-g1b+1)
			return true
		})
		crafted("z out of range and the hints malformed", func(s []byte) bool {
			setZ(s, 0, 0, 0)
			y(s)[p.omega+p.k-1] = byte(p.omega + 1)
			return true
		})
		crafted("z out of range and c~ tampered", func(s []byte) bool {
			setZ(s, 0, 0, 0)
			s[0] ^= 1
			return true
		})
		crafted("c~ all zero", func(s []byte) bool {
			for j := 0; j < p.lambda/4; j++ {
				s[j] = 0
			}
			return true
		})
		crafted("all-zero signature", func(s []byte) bool {
			for j := range s {
				s[j] = 0
			}
			return true
		})
		crafted("all-0xff signature", func(s []byte) bool {
			for j := range s {
				s[j] = 0xff
			}
			return true
		})

		// ---- forged, for the rules no honest signature reaches ----
		beta := int64(p.tau * p.eta)
		gb := int64(1)<<p.gamma1 - beta
		forged := func(what string, msg []byte, accept func(attempt) bool) {
			sig := forgeSign(fk, msg, accept, 200000)
			if sig == nil {
				die("forger: %s: %s: not found", goParams(c), what)
			}
			none(add(base{fmt.Sprintf("%s, forged: %s", goParams(c), what), c, pk0, msg, sig}))
		}
		forged("||z|| = γ1 − β − 1, the largest allowed", message(33, c), func(a attempt) bool {
			return a.zmax == gb-1 && !a.r0Fail && !a.ct0Fail
		})
		forged("||z|| = γ1 − β, otherwise valid", message(34, c), func(a attempt) bool {
			return a.zmax == gb && !a.r0Fail && !a.ct0Fail
		})
		forged("rejected by the signer's r0 bound, not the verifier's concern", message(35, c), func(a attempt) bool {
			return a.zmax < gb && a.r0Fail && !a.ct0Fail
		})
		forged("rejected by the signer's r0 bound, second", message(36, c), func(a attempt) bool {
			return a.zmax < gb && a.r0Fail
		})

		// ---- forged on a key with t1 = 0, and whether Go must take each ----
		rho := pk0[:32]
		m := int64((q - 1) / (2 * ((q - 1) / p.gamma2)))
		zeroT1 := func(what string, valid bool, salt int, fixZ func(z [][]int64), pick func(r1, r0 [][]int64) [][]int) {
			msg := message(40+salt, c)
			pk, sig := forgeZeroT1(c, rho, msg, fixZ, pick)
			if sig == nil {
				die("forger: %s: t1 = 0, %s: not found", goParams(c), what)
			}
			pub, err := mldsa.NewPublicKey(goParams(c), pk)
			if err != nil {
				die("forger: %s: %v", what, err)
			}
			if err := mldsa.Verify(pub, msg, sig, nil); (err == nil) != valid {
				die("forger: %s: t1 = 0, %s: Go says %v", goParams(c), what, err)
			}
			none(add(base{fmt.Sprintf("%s, forged with t1 = 0: %s", goParams(c), what), c, pk, msg, sig}))
		}
		// Hints at up to `max` positions where want(r1, r0) holds, nil when there are fewer than `min`.
		where := func(min, max int, want func(r1, r0 int64) bool) func(r1, r0 [][]int64) [][]int {
			return func(r1, r0 [][]int64) [][]int {
				h := make([][]int, p.k)
				total := 0
				for i := range r1 {
					for j := range r1[i] {
						if total < max && want(r1[i][j], r0[i][j]) {
							h[i] = append(h[i], j)
							total++
						}
					}
				}
				if total < min {
					return nil
				}
				return h
			}
		}
		anywhere := func(r1, r0 int64) bool { return true }
		zeroT1("no hints", true, 0, nil, where(0, 0, anywhere))
		zeroT1("hints where LowBits is exactly 0", true, 1, nil, where(1, p.omega, func(r1, r0 int64) bool { return r0 == 0 }))
		zeroT1("hints where LowBits is exactly 1 or −1", true, 2, nil, where(1, p.omega, func(r1, r0 int64) bool { return r0 == 1 || r0 == -1 }))
		zeroT1("hints where r1 = 0 and LowBits ≤ 0, wrapping to m − 1", true, 4, nil,
			where(1, p.omega/2, func(r1, r0 int64) bool { return r1 == 0 && r0 <= 0 }))
		zeroT1("hints where r1 = m − 1 and LowBits > 0, wrapping to 0", true, 5, nil,
			where(1, p.omega/2, func(r1, r0 int64) bool { return r1 == m-1 && r0 > 0 }))
		zeroT1("exactly ω hints", true, 6, nil, where(p.omega, p.omega, anywhere))
		zeroT1("ω hints, all in the last polynomial", true, 7, nil, func(r1, r0 [][]int64) [][]int {
			h := make([][]int, p.k)
			for j := 0; j < p.omega; j++ {
				h[p.k-1] = append(h[p.k-1], j*3)
			}
			return h
		})
		zeroT1("hints at 0 and 255 of every polynomial", true, 8, nil, func(r1, r0 [][]int64) [][]int {
			h := make([][]int, p.k)
			for i := range h {
				h[i] = []int{0, 255}
			}
			return h
		})
		edge := func(v int64) func(z [][]int64) {
			return func(z [][]int64) { z[p.l-1][7] = v }
		}
		zeroT1("z = γ1 − β − 1", true, 0, edge(gb-1), where(0, 0, anywhere))
		zeroT1("z = −(γ1 − β − 1)", true, 0, edge(-(gb - 1)), where(0, 0, anywhere))
		zeroT1("z = γ1 − β", false, 0, edge(gb), where(0, 0, anywhere))
		zeroT1("z = −(γ1 − β)", false, 0, edge(-gb), where(0, 0, anywhere))
		zeroT1("z = γ1", false, 0, edge(int64(1)<<p.gamma1), where(0, 0, anywhere))
		zeroT1("z = −γ1 + 1", false, 0, edge(1-int64(1)<<p.gamma1), where(0, 0, anywhere))
	}

	// ---- Go's answers ----
	texts := []string{""}
	ids := map[string]int{"": 0}
	id := func(s string) int {
		if i, ok := ids[s]; ok {
			return i
		}
		ids[s] = len(texts)
		texts = append(texts, s)
		return len(texts) - 1
	}
	type answer struct{ pk, ver int }
	answers := make([]answer, len(ms))
	count := map[string]int{}
	for i, m := range ms {
		tp, tv := verdict(bs, m)
		answers[i] = answer{id(tp), id(tv)}
		count[tv]++
	}
	for _, b := range bs {
		if strings.Contains(b.what, "forged: ||z|| = γ1 − β − 1") {
			pub, _ := mldsa.NewPublicKey(goParams(b.params), b.pk)
			if err := mldsa.Verify(pub, b.msg, b.sig, nil); err != nil {
				die("%s: Go refuses it: %v", b.what, err)
			}
		}
	}

	// ---- the header ----
	var pool []byte
	offs := map[string]int{}
	put := func(b []byte) int {
		if o, ok := offs[string(b)]; ok {
			return o
		}
		o := len(pool)
		// A search for an equal run already in the pool is not worth it; identical buffers are
		// shared through the map.
		pool = append(pool, b...)
		offs[string(b)] = o
		return o
	}
	// A signature that is another base's with a few bytes changed — most crafted ones — is written
	// as that base and the bytes, which keeps the header at half the size.
	type edit struct {
		pos int
		val byte
	}
	var edits []edit
	type loc struct{ pk, msg, sig, from, edit, nedit int }
	locs := make([]loc, len(bs))
	for i, b := range bs {
		locs[i] = loc{pk: put(b.pk), msg: put(b.msg), sig: -1, from: -1}
		best, bestN := -1, 73
		for j := 0; j < i; j++ {
			if locs[j].from >= 0 || len(bs[j].sig) != len(b.sig) {
				continue
			}
			d := 0
			for k := range b.sig {
				if b.sig[k] != bs[j].sig[k] {
					d++
				}
			}
			if d < bestN {
				best, bestN = j, d
			}
		}
		if best < 0 {
			locs[i].sig = put(b.sig)
			continue
		}
		locs[i].from, locs[i].edit = best, len(edits)
		for k := range b.sig {
			if b.sig[k] != bs[best].sig[k] {
				edits = append(edits, edit{k, b.sig[k]})
			}
		}
		locs[i].nedit = len(edits) - locs[i].edit
	}

	var w strings.Builder
	w.WriteString("/* Generated by tools/mldsavec from Go 1.27.1's own crypto/mldsa (NewPublicKey, Verify with\n")
	w.WriteString(" * nil options); see its header for how to regenerate. Do not edit. */\n")
	w.WriteString("#ifndef LC_MLDSA_REFERENCE_H\n#define LC_MLDSA_REFERENCE_H\n\n#include <stdint.h>\n\n")
	w.WriteString("static const uint8_t mv_pool[] = {\n")
	for i, c := range pool {
		if i%24 == 0 {
			w.WriteString("   ")
		}
		fmt.Fprintf(&w, " %d,", c)
		if i%24 == 23 || i == len(pool)-1 {
			w.WriteString("\n")
		}
	}
	w.WriteString("};\n\n")
	w.WriteString("/* Go's error texts; \"\" is no error. */\nstatic const char *const mv_texts[] = {\n")
	for _, t := range texts {
		fmt.Fprintf(&w, "    %q,\n", t)
	}
	w.WriteString("};\n\n")
	w.WriteString("/* Bytes set in another base's signature: see mv_base. */\n")
	w.WriteString("struct mv_edit {\n    uint16_t pos;\n    uint8_t  val;\n};\n\n")
	w.WriteString("static const struct mv_edit mv_edits[] = {\n")
	for i, e := range edits {
		if i%8 == 0 {
			w.WriteString("   ")
		}
		fmt.Fprintf(&w, " {%d, %d},", e.pos, e.val)
		if i%8 == 7 || i == len(edits)-1 {
			w.WriteString("\n")
		}
	}
	w.WriteString("};\n\n")
	w.WriteString("/* A key, a message and a signature: params is LC_MLDSA_44/65/87. The signature is sig_len\n")
	w.WriteString(" * bytes of the pool at sig, or — when from is not -1 — base from's signature with the bytes of\n")
	w.WriteString(" * mv_edits[edit .. edit+nedit) set. */\n")
	w.WriteString("struct mv_base {\n    const char *what;\n    uint8_t     params;\n    uint32_t    pk, pk_len, msg, msg_len, sig, sig_len;\n    int16_t     from;\n    uint16_t    edit, nedit;\n};\n\n")
	w.WriteString("static const struct mv_base mv_bases[] = {\n")
	for i, b := range bs {
		sig := locs[i].sig
		if sig < 0 {
			sig = 0
		}
		fmt.Fprintf(&w, "    {%q, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d},\n", b.what, b.params, locs[i].pk, len(b.pk),
			locs[i].msg, len(b.msg), sig, len(b.sig), locs[i].from, locs[i].edit, locs[i].nedit)
	}
	w.WriteString("};\n\n")
	w.WriteString("/* A base, changed: target 0 nothing, 1 the key, 2 the message, 3 the signature; op 1 xors val\n")
	w.WriteString(" * into byte pos, 2 sets it, 3 cuts to pos bytes, 4 appends pos bytes of val. The call is made\n")
	w.WriteString(" * with params (0: Go's zero mldsa.Parameters{}). t_pk is NewPublicKey's text, t_ver Verify's. */\n")
	w.WriteString("struct mv_case {\n    uint16_t base;\n    uint8_t  params, target, op, val;\n    uint32_t pos;\n    uint8_t  t_pk, t_ver;\n};\n\n")
	w.WriteString("static const struct mv_case mv_cases[] = {\n")
	for i, m := range ms {
		fmt.Fprintf(&w, "    {%d, %d, %d, %d, %d, %d, %d, %d},\n", m.base, m.params, m.target, m.op, m.val, m.pos,
			answers[i].pk, answers[i].ver)
	}
	w.WriteString("};\n\n#endif\n")
	os.Stdout.WriteString(w.String())

	fmt.Fprintf(os.Stderr, "%d bases, %d cases, pool %d bytes\n", len(bs), len(ms), len(pool))
	for _, t := range texts {
		fmt.Fprintf(os.Stderr, "  %6d  %q\n", count[t], t)
	}
}
