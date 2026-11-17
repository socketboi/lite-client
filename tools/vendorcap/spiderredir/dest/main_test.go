package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The runtime fixtures below verify that note preserves its supplied clock. This source
// invariant also guards where the actual Read/Write wrappers obtain that clock, without
// a timed mutex-contention test or a clock-injection hook in the measuring server.
func TestCaptureWrappersClockBoundary(t *testing.T) {
	source, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var selector func(ast.Expr) string
	selector = func(e ast.Expr) string {
		switch n := e.(type) {
		case *ast.Ident:
			return n.Name
		case *ast.SelectorExpr:
			return selector(n.X) + "." + n.Sel.Name
		default:
			return ""
		}
	}
	for _, method := range []string{"Read", "Write"} {
		t.Run(method, func(t *testing.T) {
			var body *ast.BlockStmt
			for _, decl := range source.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != method || fn.Recv == nil || len(fn.Recv.List) != 1 {
					continue
				}
				receiver, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
				if ok && selector(receiver.X) == "capture" {
					body = fn.Body
				}
			}
			if body == nil {
				t.Fatalf("missing capture.%s", method)
			}
			ioAt, clockAt, lockAt, noteAt := -1, -1, -1, -1
			for i, stmt := range body.List {
				switch n := stmt.(type) {
				case *ast.AssignStmt:
					for _, rhs := range n.Rhs {
						if call, ok := rhs.(*ast.CallExpr); ok && selector(call.Fun) == "c.Conn."+method {
							ioAt = i
						}
					}
				case *ast.IfStmt:
					if selector(n.Cond) != "c.timing" || len(n.Body.List) != 1 || n.Else != nil {
						continue
					}
					assign, ok := n.Body.List[0].(*ast.AssignStmt)
					if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || selector(assign.Lhs[0]) != "completed" {
						continue
					}
					call, ok := assign.Rhs[0].(*ast.CallExpr)
					if ok && selector(call.Fun) == "time.Now" && len(call.Args) == 0 {
						clockAt = i
					}
				case *ast.ExprStmt:
					call, ok := n.X.(*ast.CallExpr)
					if !ok {
						continue
					}
					if selector(call.Fun) == "c.mu.Lock" {
						lockAt = i
					}
					if selector(call.Fun) == "c.note" && len(call.Args) == 3 && selector(call.Args[2]) == "completed" {
						noteAt = i
					}
				}
			}
			if ioAt < 0 || clockAt != ioAt+2 || clockAt >= lockAt || lockAt >= noteAt {
				t.Fatalf("%s clock must follow I/O immediately and precede capture mutex/note: I/O=%d clock=%d lock=%d note=%d", method, ioAt, clockAt, lockAt, noteAt)
			}
			// Only zero-initializing the local timestamp may intervene before time.Now.
			decl, ok := body.List[ioAt+1].(*ast.DeclStmt)
			if !ok {
				t.Fatal("work inserted between I/O and timestamp")
			}
			gen, ok := decl.Decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR || len(gen.Specs) != 1 {
				t.Fatal("unexpected timestamp declaration")
			}
			v, ok := gen.Specs[0].(*ast.ValueSpec)
			if !ok || len(v.Names) != 1 || v.Names[0].Name != "completed" || selector(v.Type) != "time.Time" || len(v.Values) != 0 {
				t.Fatal("timestamp declaration does work before the clock")
			}
		})
	}
}

func testFrame(typ, flags byte, sid byte, payload []byte) []byte {
	b := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags, 0, 0, 0, sid}
	return append(b, payload...)
}

func TestNoteUsesIOCompletion(t *testing.T) {
	for _, dir := range []string{"r", "w"} {
		t.Run(dir, func(t *testing.T) {
			base := time.Now().Add(-time.Second)
			c := &capture{timing: true, t0: base}
			// A known earlier I/O boundary must not be replaced by the time of parsing.
			c.note(dir, testFrame(1, 5, 1, nil), base.Add(17*time.Microsecond))
			if len(c.events) != 1 || !strings.HasPrefix(c.events[0], dir+"+17 HEADERS1e capture+") {
				t.Fatalf("wrong I/O boundary: %v", c.events)
			}
		})
	}
}

func TestNoteCompletesSplitFramesAndPreface(t *testing.T) {
	base := time.Now().Add(-time.Second)
	c := &capture{timing: true, t0: base, skipPref: len(preface)}
	b := append([]byte(preface), testFrame(4, 0, 0, nil)...)
	b = append(b, testFrame(1, 5, 1, []byte{0x82})...)
	for i, chunk := range [][]byte{b[:7], b[7 : len(b)-1], b[len(b)-1:]} {
		c.note("r", chunk, base.Add(time.Duration(i+1)*time.Microsecond))
	}
	if !strings.HasPrefix(c.events[0], "r+1  capture+") ||
		!strings.HasPrefix(c.events[1], "r+2 SETTINGS capture+") ||
		!strings.HasPrefix(c.events[2], "r+3 HEADERS1e capture+") {
		t.Fatalf("incorrect frame completion boundaries: %v", c.events)
	}
}

type fixtureConn struct {
	net.Conn
	read   []byte
	writeN int
	err    error
	closed bool
}

func (c *fixtureConn) Read(b []byte) (int, error)  { return copy(b, c.read), c.err }
func (c *fixtureConn) Write(b []byte) (int, error) { return min(len(b), c.writeN), c.err }
func (c *fixtureConn) Close() error                { c.closed = true; return nil }

func TestReadCapturesBytesAlongsideError(t *testing.T) {
	b := testFrame(1, 5, 1, nil)
	c := &capture{Conn: &fixtureConn{read: b, err: io.EOF}, timing: true, t0: time.Now()}
	n, err := c.Read(make([]byte, 32))
	if n != len(b) || err != io.EOF || !bytes.Equal(c.got, b) ||
		len(c.events) != 1 || !strings.Contains(c.events[0], " HEADERS1e capture+") {
		t.Fatalf("partial/error read changed: n=%d err=%v got=%x events=%v", n, err, c.got, c.events)
	}
}

func TestWriteCapturesOnlyWrittenBytes(t *testing.T) {
	first := testFrame(1, 5, 1, nil)
	b := append(append([]byte(nil), first...), testFrame(0, 1, 1, nil)...)
	conn := &fixtureConn{writeN: len(first), err: io.ErrShortWrite}
	c := &capture{Conn: conn, timing: true, t0: time.Now(), closeAfter: true}
	n, err := c.Write(b)
	if n != len(first) || err != io.ErrShortWrite || conn.closed || c.closed ||
		len(c.events) != 1 || !strings.Contains(c.events[0], " HEADERS1e capture+") ||
		strings.Contains(c.events[0], "DATA") {
		t.Fatalf("unwritten END_STREAM observed: n=%d err=%v closed=%v events=%v", n, err, conn.closed, c.events)
	}
}

func TestTimingOffPreservesCapture(t *testing.T) {
	b := testFrame(1, 5, 1, nil)
	c := &capture{Conn: &fixtureConn{read: b, writeN: len(b)}}
	c.Read(make([]byte, 32))
	c.Write(b)
	if !bytes.Equal(c.got, b) || len(c.events) != 0 {
		t.Fatalf("disabled timing changed capture: got=%x events=%v", c.got, c.events)
	}
}

func TestConcurrentReadWriteTiming(t *testing.T) {
	b := testFrame(1, 5, 1, nil)
	c := &capture{Conn: &fixtureConn{read: b, writeN: len(b)}, timing: true, t0: time.Now()}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for i := 0; i < 64; i++ {
			c.Read(make([]byte, 32))
		}
	}()
	go func() {
		defer workers.Done()
		for i := 0; i < 64; i++ {
			c.Write(b)
		}
	}()
	workers.Wait()
	if len(c.events) != 128 || len(c.got) != 64*len(b) {
		t.Fatalf("lost concurrent capture: events=%d bytes=%d", len(c.events), len(c.got))
	}
}

func TestScenarioSpec(t *testing.T) {
	for _, test := range []struct{ input, label, scenario, sample string }{
		{"ref bigbody", "ref", "bigbody", ""},
		{"lc bigbody 10\n", "lc", "bigbody", "10"},
		{"ref bigbody 20", "ref", "bigbody", "20"},
		{"ref bigbody 0", "?", "none", ""},
		{"ref bigbody 21", "?", "none", ""},
		{"ref bigbody 01", "?", "none", ""},
		{"ref bigbody bad", "?", "none", ""},
		{"ref bigbody 1 extra", "?", "none", ""},
	} {
		label, scenario, sample := scenarioSpec([]byte(test.input))
		if label != test.label || scenario != test.scenario || sample != test.sample {
			t.Fatalf("%q: got %q %q %q", test.input, label, scenario, sample)
		}
	}
}

func TestDecodePreservesSampleAndClock(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old; r.Close(); w.Close() }()
	decode("ref", "bigbody", []byte(preface), []string{"r+17 HEADERS1e capture+2"}, "10")
	w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ref bigbody |", "  sample 10\n", "  PREFACE #1\n", "  timing clock=io-return-v2\n", "  timing r+17 HEADERS1e capture+2\n"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing %q in %q", want, b)
		}
	}
}
