// Chains made to reach what crypto/x509's own tests leave alone — run under the same overlay as
// they are (test/goverify/run.sh), so every Verify here is recorded by zz_record.go the same way.
//
// Six rules of Certificate.Verify survived as mutants against Go's tests alone, and each has
// scenarios here that tell the rule from its mutant:
//
//   - the order findPotentialParents tries candidates in: matching key ID, then one side without
//     one, then the rest (cert_pool.go) — seen in the order of the chains and in which failure the
//     error names;
//   - VerifyHostname's pattern rules: a hyphen that begins a label, a '*' that is not the whole
//     first label, trailing dots, case, IPs with and without brackets and zones;
//   - the '.' below '-' in dnsCompare, which decides which of "a.com", "a-a.com", "a.a.com" the
//     pruning keeps;
//   - slices.SortFunc on fifty and more constraints (the partial insertion sort's shifting, which
//     needs at least fifty), with case variants that compare equal, whose survivor the error names;
//   - CheckSignatureFrom refusing a parent whose KeyUsage lacks certSign;
//   - UnknownAuthorityError naming the FIRST candidate that failed.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	serial   int64
	notAfter = time.Unix(2000000000, 0)
	now      = time.Unix(1800000000, 0)
)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func key() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		panic(err)
	}
	return k
}

func make1(t *x509.Certificate, parent *ca, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	serial++
	t.SerialNumber = big.NewInt(serial)
	if t.NotBefore.IsZero() {
		t.NotBefore = time.Unix(1700000000, 0)
	}
	if t.NotAfter.IsZero() {
		t.NotAfter = notAfter
	}
	p := t
	if parent != nil {
		p = parent.cert
	}
	der, err := x509.CreateCertificate(nil, t, p, pub, signer)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}

func root(cn string, mod func(*x509.Certificate)) *ca {
	k := key()
	t := &x509.Certificate{Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	if mod != nil {
		mod(t)
	}
	return &ca{make1(t, nil, &k.PublicKey, k), k}
}

func inter(cn string, parent *ca, k *ecdsa.PrivateKey, mod func(*x509.Certificate)) *ca {
	if k == nil {
		k = key()
	}
	t := &x509.Certificate{Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	if mod != nil {
		mod(t)
	}
	return &ca{make1(t, parent, &k.PublicKey, parent.key), k}
}

func leaf(parent *ca, mod func(*x509.Certificate)) *x509.Certificate {
	k := key()
	t := &x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}, DNSNames: []string{"leaf.example"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if mod != nil {
		mod(t)
	}
	return make1(t, parent, &k.PublicKey, parent.key)
}

func pool(cs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range cs {
		p.AddCert(c)
	}
	return p
}

func verify(l *x509.Certificate, roots, inters *x509.CertPool, dns string) {
	l.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: dns, CurrentTime: now})
}

func hostnames() {
	r := root("host root", nil)
	patterns := []string{"*.example.com", "a*.example.com", "*", "*.*.example.com", "-a.example.com",
		"a-.example.com", "a_b.example.com", "EXAMPLE.com", "example.com.", ".example.com",
		"x.*.example.com", "*.example.com.", "xn--e1a.com", "a..example.com",
		"*.com", "*a.example.com", "a", "A-B.Example.COM"}
	hosts := []string{"a.example.com", "example.com", "-a.example.com", "a-.example.com", "A.EXAMPLE.COM",
		"a.example.com.", "a.b.example.com", "*.example.com", "a_b.example.com", "x.y.example.com",
		"é.example.com", "a..example.com", ".example.com", "a", "a-b.example.com", "aa.example.com",
		"[a.example.com]", "example.com..", "."}
	for _, p := range patterns {
		l := leaf(r, func(t *x509.Certificate) { t.DNSNames = []string{p} })
		for _, h := range hosts {
			verify(l, pool(r.cert), nil, h)
		}
	}
	ips := leaf(r, func(t *x509.Certificate) {
		t.DNSNames = nil
		t.IPAddresses = []net.IP{net.ParseIP("192.0.2.1").To4(), net.ParseIP("2001:db8::1"), net.ParseIP("fe80::1")}
	})
	noSAN := leaf(r, func(t *x509.Certificate) { t.DNSNames = nil; t.Subject.CommonName = "cn.example" })
	// a Common Name is never matched, but HostnameError says when it would have been, through
	// matchHostnames — which takes a '*' only as the whole first label
	for _, cn := range []string{"*.cn.example", "a.*.cn.example", "*.*.cn.example", "A.CN.example", "cn.example."} {
		l := leaf(r, func(t *x509.Certificate) { t.DNSNames = nil; t.Subject.CommonName = cn })
		for _, h := range []string{"a.cn.example", "a.b.cn.example", "a.cn.example.", "cn.example", "x.a.cn.example"} {
			verify(l, pool(r.cert), nil, h)
		}
	}
	for _, h := range []string{"192.0.2.1", "[192.0.2.1]", "::ffff:192.0.2.1", "[::ffff:192.0.2.1]",
		"2001:db8::1", "[2001:db8::1]", "2001:DB8::1", "fe80::1%eth0", "[fe80::1%eth0]", "192.0.2.2",
		"[2001:db8::2]", "cn.example", "CN.example.", "192.0.2.1.", "[]", "[x]"} {
		verify(ips, pool(r.cert), nil, h)
		verify(noSAN, pool(r.cert), nil, h)
	}
}

// Candidates with the leaf's issuer name, in every combination of key-ID relation and fault.
func candidates() {
	r := root("cand root", nil)
	iss := key()
	// the leaf's AuthorityKeyId is the issuer's SubjectKeyId as CreateCertificate derives it; the
	// candidates share the name and the key and differ in their SubjectKeyId and faults
	kinds := []struct {
		name string
		skid []byte
	}{{"match", nil}, {"none", []byte{}}, {"other", []byte{1, 2, 3}}}
	faults := []struct {
		name string
		mod  func(*x509.Certificate)
	}{
		{"good", nil},
		{"expired", func(t *x509.Certificate) { t.NotAfter = time.Unix(1750000000, 0) }},
		{"not a CA", func(t *x509.Certificate) { t.IsCA = false }},
		{"no certSign", func(t *x509.Certificate) { t.KeyUsage = x509.KeyUsageDigitalSignature }},
		{"no key usage", func(t *x509.Certificate) { t.KeyUsage = 0 }},
		{"path length 0 under another", func(t *x509.Certificate) { t.MaxPathLen = 0; t.MaxPathLenZero = true }},
	}
	base := inter("the issuer", r, iss, nil)
	for i, a := range kinds {
		for j, b := range kinds {
			if i == j {
				continue
			}
			for _, fa := range faults {
				for _, fb := range faults {
					mk := func(k struct {
						name string
						skid []byte
					}, f func(*x509.Certificate)) *x509.Certificate {
						return inter("the issuer", r, iss, func(t *x509.Certificate) {
							switch {
							case k.name == "none":
								// CreateCertificate gives every CA a SubjectKeyId; an empty one
								// written as an extra extension stands in its place, and parses
								// to none (x509.go:1328)
								t.ExtraExtensions = []pkix.Extension{{Id: []int{2, 5, 29, 14}, Value: []byte{0x04, 0x00}}}
							case k.name != "match":
								t.SubjectKeyId = k.skid
							default:
								t.SubjectKeyId = base.cert.SubjectKeyId
							}
							if f != nil {
								f(t)
							}
						}).cert
					}
					ca1, ca2 := mk(a, fa.mod), mk(b, fb.mod)
					l := leaf(&ca{base.cert, iss}, nil)
					verify(l, pool(r.cert), pool(ca1, ca2), "leaf.example")
					// the same two as roots
					verify(l, pool(ca1, ca2), nil, "leaf.example")
				}
			}
		}
	}
	// a leaf without an AuthorityKeyId
	noAKID := leaf(&ca{base.cert, iss}, func(t *x509.Certificate) { t.AuthorityKeyId = nil })
	for _, f := range faults {
		c := inter("the issuer", r, iss, f.mod).cert
		verify(noAKID, pool(r.cert), pool(c, base.cert), "leaf.example")
		verify(noAKID, pool(c, base.cert), nil, "leaf.example")
	}
}

// Name constraints whose order after sorting decides what is kept and what the error names.
func constraints() {
	for _, set := range [][]string{
		{"a.com", "a-a.com", "a.a.com"},
		{"a.a.com", "a-a.com", "a.com"},
		{"a-a.com", "a.com", "b.a.com", ".a.com", "a--a.com", "a.-a.com"},
	} {
		for _, excl := range []bool{false, true} {
			r := root("nc root", func(t *x509.Certificate) {
				if excl {
					t.ExcludedDNSDomains = set
				} else {
					t.PermittedDNSDomains = set
				}
			})
			for _, n := range []string{"a.com", "a-a.com", "a.a.com", "x.a.a.com", "x.a-a.com", "b.a.com", "a--a.com",
				"x.a.com", "*.a.com", "*.a-a.com", "aa.com"} {
				l := leaf(r, func(t *x509.Certificate) { t.DNSNames = []string{n} })
				verify(l, pool(r.cert), nil, "")
			}
		}
	}
	// fifty and more, with case variants of one name spread through them
	for _, count := range []int{12, 13, 49, 50, 51, 64, 100, 130} {
		for seed := 0; seed < 4; seed++ {
			var set []string
			for i := 0; i < count; i++ {
				v := (i*7919 + seed*104729) % 1000
				switch v % 5 {
				case 0:
					set = append(set, fmt.Sprintf("n%03d.example.com", v))
				case 1:
					set = append(set, fmt.Sprintf("N%03d.EXAMPLE.com", v-1))
				case 2:
					set = append(set, fmt.Sprintf(".sub%02d.example.org", v%37))
				case 3:
					set = append(set, "Target.Example.NET", "target.example.net", "TARGET.example.net")
				default:
					set = append(set, fmt.Sprintf("x%d-y.example.com", v%17))
				}
			}
			for _, excl := range []bool{true, false} {
				r := root("sort root", func(t *x509.Certificate) {
					if excl {
						t.ExcludedDNSDomains = set
					} else {
						t.PermittedDNSDomains = set
					}
				})
				for _, n := range []string{"target.example.net", "a.target.example.net", "n000.example.com",
					"q.sub03.example.org", "x5-y.example.com", "nothing.example"} {
					l := leaf(r, func(t *x509.Certificate) { t.DNSNames = []string{n} })
					verify(l, pool(r.cert), nil, "")
				}
			}
		}
	}
	// URIs, IPs and mailboxes under constraints, and wildcards against excluded parents
	u := func(s string) *url.URL {
		v, err := url.Parse(s)
		if err != nil {
			panic(err)
		}
		return v
	}
	r := root("mixed root", func(t *x509.Certificate) {
		t.ExcludedDNSDomains = []string{"Bad.Example", "x.EVIL.example"}
		t.ExcludedURIDomains = []string{".evil.example"}
		t.PermittedEmailAddresses = []string{"Joe@Example.com", "example.org"}
		_, n1, _ := net.ParseCIDR("10.0.0.0/8")
		_, n2, _ := net.ParseCIDR("10.1.0.0/16")
		t.PermittedIPRanges = []*net.IPNet{n2, n1}
	})
	for _, mod := range []func(*x509.Certificate){
		func(t *x509.Certificate) { t.DNSNames = []string{"*.evil.example"} },
		func(t *x509.Certificate) { t.DNSNames = []string{"*.x.evil.EXAMPLE"} },
		func(t *x509.Certificate) { t.DNSNames = []string{"*.bad.example"} },
		func(t *x509.Certificate) { t.URIs = []*url.URL{u("https://A.EVIL.example:8443/p")} },
		func(t *x509.Certificate) { t.URIs = []*url.URL{u("https://good.example/")} },
		func(t *x509.Certificate) { t.URIs = []*url.URL{u("https://[::1]/")} },
		func(t *x509.Certificate) { t.EmailAddresses = []string{"joe@EXAMPLE.com"} },
		func(t *x509.Certificate) { t.EmailAddresses = []string{"Joe@example.com"} },
		func(t *x509.Certificate) { t.EmailAddresses = []string{"joe@x.example.org"} },
		func(t *x509.Certificate) { t.EmailAddresses = []string{`"j\oe"@example.org`} },
		func(t *x509.Certificate) { t.IPAddresses = []net.IP{net.IP{10, 1, 2, 3}} },
		func(t *x509.Certificate) { t.IPAddresses = []net.IP{net.IP{11, 1, 2, 3}} },
		func(t *x509.Certificate) { t.IPAddresses = []net.IP{net.ParseIP("2001:db8::1")} },
	} {
		l := leaf(r, mod)
		verify(l, pool(r.cert), nil, "")
	}
}

// Two candidates that both fail, and the error names the first.
func hints() {
	r := root("hint root", nil)
	iss := key()
	good := inter("hinted", r, iss, nil)
	for _, pair := range [][2]func(*x509.Certificate){
		{func(t *x509.Certificate) { t.NotAfter = time.Unix(1750000000, 0) }, func(t *x509.Certificate) { t.IsCA = false }},
		{func(t *x509.Certificate) { t.IsCA = false }, func(t *x509.Certificate) { t.NotAfter = time.Unix(1750000000, 0) }},
		// both refused by CheckSignatureFrom, which leaves err alone: then the error is
		// UnknownAuthorityError, and it names the first
		{func(t *x509.Certificate) { t.IsCA = false }, func(t *x509.Certificate) { t.KeyUsage = x509.KeyUsageDigitalSignature }},
		{func(t *x509.Certificate) { t.KeyUsage = x509.KeyUsageDigitalSignature }, func(t *x509.Certificate) { t.IsCA = false }},
		{func(t *x509.Certificate) { t.IsCA = false }, nil},
		{nil, func(t *x509.Certificate) { t.IsCA = false }},
	} {
		// a nil fault is a candidate signed by another key: its signature fails
		mk := func(f func(*x509.Certificate)) *x509.Certificate {
			if f == nil {
				return inter("hinted", r, nil, nil).cert
			}
			return inter("hinted", r, iss, f).cert
		}
		a, b := mk(pair[0]), mk(pair[1])
		l := leaf(&ca{good.cert, iss}, nil)
		verify(l, pool(a, b), nil, "leaf.example")
		verify(l, pool(b, a), nil, "leaf.example")
		verify(l, x509.NewCertPool(), pool(a, b), "leaf.example")
	}
}

func main() {
	if os.Getenv("X509REC_OUT") == "" {
		fmt.Fprintln(os.Stderr, "cases: run under test/goverify/run.sh, which records what Verify answers")
		os.Exit(2)
	}
	hostnames()
	candidates()
	constraints()
	hints()
	_ = strings.ToLower
}
