// Every Certificate.Verify and every policiesValid that crypto/x509's own tests make, written
// down with its answer — what test/goverify holds cert/goverify.c to (see cert/goverify.h).
//
// NOT A PROGRAM AND NOT A TEST: a file of package x509 itself, dropped into go1.27.1's
// GOROOT/src/crypto/x509 next to a verify.go whose Verify and policiesValid have been renamed
// verifyInner and policiesValidInner, so that these two wrappers stand where they stood and every
// caller — the package's tests included — goes through them. `go test crypto/x509` then runs
// Go's whole table of chains: verify_test.go (path building, cross-signatures, the signature
// budget, EKU nesting, policies, hostnames), name_constraints_test.go, and the rest. See gen.sh for
// the whole procedure; main.go turns the record into test/goverify/reference.h.
//
// What is kept: calls whose roots are an explicit pool of parsed certificates, no pool entry
// carrying a constraint function (AddCertWithConstraint — nothing outside tests uses it), and no
// certificate that a test changed after parsing it (re-parsed from Raw and compared), since the C
// side starts from the bytes. CurrentTime, when the caller left it zero, is fixed to the moment of
// the call and recorded, so that both sides judge validity at the same instant.
package x509

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

var (
	recMu    sync.Mutex
	recFile  *os.File
	recCerts = map[string]int{}
)

func recOut() *os.File {
	if recFile == nil {
		path := os.Getenv("X509REC_OUT")
		if path == "" {
			return nil
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			panic(err)
		}
		recFile = f
	}
	return recFile
}

// recCert gives the certificate its number in the record, writing it the first time it is seen;
// -1 when the certificate is not what its bytes say.
func recCert(f *os.File, c *Certificate) int {
	if c == nil || len(c.Raw) == 0 {
		return -1
	}
	again, err := ParseCertificate(c.Raw)
	if err != nil || !reflect.DeepEqual(again, c) {
		return -1
	}
	key := string(c.Raw)
	if i, ok := recCerts[key]; ok {
		return i
	}
	i := len(recCerts)
	recCerts[key] = i
	fmt.Fprintf(f, "C|%d|%s\n", i, hex.EncodeToString(c.Raw))
	return i
}

// recPool: the pool's certificates in its own order, or ok false when one cannot be recorded.
func recPool(f *os.File, p *CertPool) (idx []string, ok bool) {
	if p == nil {
		return nil, true
	}
	if p.systemPool {
		return nil, false
	}
	for i := 0; i < p.len(); i++ {
		c, constraint, err := p.cert(i)
		if err != nil || constraint != nil {
			return nil, false
		}
		n := recCert(f, c)
		if n < 0 {
			return nil, false
		}
		idx = append(idx, fmt.Sprint(n))
	}
	return idx, true
}

func recOpts(opts *VerifyOptions) string {
	var ekus, pols []string
	for _, u := range opts.KeyUsages {
		ekus = append(ekus, fmt.Sprint(int(u)))
	}
	for _, p := range opts.CertificatePolicies {
		pols = append(pols, hex.EncodeToString(p.der))
	}
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	return fmt.Sprintf("%s|%s|%d%d%d", strings.Join(ekus, ","), strings.Join(pols, ","),
		b(opts.inhibitPolicyMapping), b(opts.requireExplicitPolicy), b(opts.inhibitAnyPolicy))
}

func (c *Certificate) Verify(opts VerifyOptions) ([][]*Certificate, error) {
	if opts.CurrentTime.IsZero() {
		opts.CurrentTime = time.Now()
	}
	chains, err := c.verifyInner(opts)
	recMu.Lock()
	defer recMu.Unlock()
	f := recOut()
	if f == nil || opts.Roots == nil {
		return chains, err
	}
	leaf := recCert(f, c)
	roots, ok1 := recPool(f, opts.Roots)
	inters, ok2 := recPool(f, opts.Intermediates)
	if leaf < 0 || !ok1 || !ok2 || opts.MaxConstraintComparisions != 0 {
		return chains, err
	}
	var result string
	if err != nil {
		result = "E:" + hex.EncodeToString([]byte(err.Error()))
	} else {
		var cs []string
		for _, ch := range chains {
			var ids []string
			for _, cc := range ch {
				n := recCert(f, cc)
				if n < 0 {
					return chains, err
				}
				ids = append(ids, fmt.Sprint(n))
			}
			cs = append(cs, strings.Join(ids, "-"))
		}
		result = "C:" + strings.Join(cs, ";")
	}
	fmt.Fprintf(f, "V|%d|%s|%s|%d|%d|%s|%s|%s\n", leaf, strings.Join(roots, ","),
		strings.Join(inters, ","), opts.CurrentTime.Unix(), opts.CurrentTime.Nanosecond(),
		hex.EncodeToString([]byte(opts.DNSName)), recOpts(&opts), result)
	return chains, err
}

func policiesValid(chain []*Certificate, opts VerifyOptions) bool {
	ok := policiesValidInner(chain, opts)
	recMu.Lock()
	defer recMu.Unlock()
	f := recOut()
	if f == nil {
		return ok
	}
	var ids []string
	for _, c := range chain {
		n := recCert(f, c)
		if n < 0 {
			return ok
		}
		ids = append(ids, fmt.Sprint(n))
	}
	r := 0
	if ok {
		r = 1
	}
	fmt.Fprintf(f, "P|%s|%s|%d\n", strings.Join(ids, "-"), recOpts(&opts), r)
	return ok
}

var _ = bytes.Equal
