package main

// The extension order a shuffling parrot starts from.
//
// Chrome is not captured in any fixed order: uTLS builds its spec as
//
//	Extensions: ShuffleChromeTLSExtensions([]TLSExtension{ &UtlsGREASEExtension{}, &SNIExtension{}, ... })
//
// inside utlsIdToSpec (vendor/utls/u_parrots.go:917 for HelloChrome_133), so every spec the library
// hands out — and every hello this tool captures — is one draw of that literal list. The client
// repeats the same skip-based swap loop (src/fp/hello.c shuffle_extensions), and that loop is not a
// uniform shuffle: an element's chance of staying at the first or last movable slot depends on where
// it STARTED. Shuffling a capture therefore composes the reference's law with whatever permutation
// the capture froze, and a few hundred hellos tell the two apart. The table has to carry the literal
// order, and the library exposes it nowhere but in its own source — so it is read from there, from
// the very module this binary is built against, rather than typed in.
//
// Also why a Chrome table is now a deterministic function of the pinned uTLS, like Firefox's.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// parrotBaseOrder returns, for the named fingerprint, the wire types of its extensions in the order
// its spec LITERALLY lists them, and whether the spec shuffles that list. GREASE comes back as the
// placeholder. parrotsSrc is the path of u_parrots.go inside the uTLS module this binary links.
func parrotBaseOrder(name, sni, parrotsSrc string) ([]uint16, bool, error) {
	dir := filepath.Dir(parrotsSrc)
	files, err := parsePackage(dir)
	if err != nil {
		return nil, false, err
	}

	// The Hysteria2 plane's parrot is not in u_parrots.go at all: its literal list is in the fork's
	// own spec, and its hello comes out of a QUIC connection rather than BuildHandshakeState. The
	// uTLS sources are still what its constructor call (BoringGREASEECH) is resolved against.
	var elems []ast.Expr
	var shuffles bool
	var ids map[string][]uint16
	if name == chromeQUIC {
		if elems, shuffles, err = quicSpecExtensions(); err != nil {
			return nil, false, err
		}
		if ids, err = quicTypeIDs(sni); err != nil {
			return nil, false, err
		}
	} else {
		id, ok := fingerprints[name]
		if !ok {
			return nil, false, fmt.Errorf("unknown fingerprint %q", name)
		}
		if elems, shuffles, err = specExtensions(files, id.Client, id.Version); err != nil {
			return nil, false, err
		}
		if ids, err = typeIDs(id, sni); err != nil {
			return nil, false, err
		}
	}
	names := make([]string, 0, len(elems))
	for _, e := range elems {
		n, err := elemTypeName(files, e)
		if err != nil {
			return nil, false, err
		}
		names = append(names, n)
	}
	out := make([]uint16, 0, len(names))
	for _, n := range names {
		q := ids[n]
		if len(q) == 0 {
			return nil, false, fmt.Errorf("spec lists %s, which the rendered hello does not carry", n)
		}
		out = append(out, normGREASE(q[0]))
		ids[n] = q[1:]
	}
	for n, q := range ids {
		if len(q) != 0 {
			return nil, false, fmt.Errorf("the rendered hello carries %s that the spec literal does not list", n)
		}
	}
	return out, shuffles, nil
}

func parsePackage(dir string) ([]*ast.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no Go files in %s", dir)
	}
	return files, nil
}

// specExtensions finds the case of utlsIdToSpec that serves (client, version) and returns the
// elements of its Extensions list, unwrapping ShuffleChromeTLSExtensions if the list is wrapped.
func specExtensions(files []*ast.File, client, version string) ([]ast.Expr, bool, error) {
	strs := map[string]string{}     // string constants: helloChrome -> "Chrome"
	idents := map[string]ast.Expr{} // package-level values by name
	for _, f := range files {
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || (g.Tok != token.CONST && g.Tok != token.VAR) {
				continue
			}
			for _, s := range g.Specs {
				vs, ok := s.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, n := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					idents[n.Name] = vs.Values[i]
					if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
						if v, err := strconv.Unquote(bl.Value); err == nil {
							strs[n.Name] = v
						}
					}
				}
			}
		}
	}
	// What a ClientHelloID identifier stands for, following aliases such as HelloChrome_Auto.
	var resolve func(name string, depth int) (string, string, bool)
	resolve = func(name string, depth int) (string, string, bool) {
		if depth > 8 {
			return "", "", false
		}
		v, ok := idents[name]
		if !ok {
			return "", "", false
		}
		switch x := v.(type) {
		case *ast.Ident:
			return resolve(x.Name, depth+1)
		case *ast.CompositeLit:
			if t, ok := x.Type.(*ast.Ident); !ok || t.Name != "ClientHelloID" || len(x.Elts) < 2 {
				return "", "", false
			}
			var c, ver string
			switch e := x.Elts[0].(type) {
			case *ast.Ident:
				c = strs[e.Name]
			case *ast.BasicLit:
				c, _ = strconv.Unquote(e.Value)
			}
			if bl, ok := x.Elts[1].(*ast.BasicLit); ok {
				ver, _ = strconv.Unquote(bl.Value)
			}
			return c, ver, c != ""
		}
		return "", "", false
	}

	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Name.Name != "utlsIdToSpec" || fd.Body == nil {
				continue
			}
			var found []ast.Expr
			var shuffles, hit bool
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if hit {
					return false
				}
				cc, ok := n.(*ast.CaseClause)
				if !ok {
					return true
				}
				match := false
				for _, e := range cc.List {
					if id, ok := e.(*ast.Ident); ok {
						if c, v, ok := resolve(id.Name, 0); ok && c == client && v == version {
							match = true
						}
					}
				}
				if !match {
					return true
				}
				for _, st := range cc.Body {
					ret, ok := st.(*ast.ReturnStmt)
					if !ok || len(ret.Results) == 0 {
						continue
					}
					lit, ok := ret.Results[0].(*ast.CompositeLit)
					if !ok {
						continue
					}
					for _, el := range lit.Elts {
						kv, ok := el.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Extensions" {
							continue
						}
						v := kv.Value
						if call, ok := v.(*ast.CallExpr); ok {
							if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "ShuffleChromeTLSExtensions" && len(call.Args) == 1 {
								shuffles = true
								v = call.Args[0]
							}
						}
						if cl, ok := v.(*ast.CompositeLit); ok {
							found = cl.Elts
							hit = true
						}
					}
				}
				return false
			})
			if hit {
				return found, shuffles, nil
			}
		}
	}
	return nil, false, fmt.Errorf("no literal Extensions list for %s %s in utlsIdToSpec", client, version)
}

// elemTypeName names the extension type one list element constructs: `&SNIExtension{...}` is
// SNIExtension, and a constructor call such as `BoringGREASEECH()` is whatever that function returns.
func elemTypeName(files []*ast.File, e ast.Expr) (string, error) {
	switch x := e.(type) {
	case *ast.UnaryExpr:
		if cl, ok := x.X.(*ast.CompositeLit); ok {
			if n := typeIdent(cl.Type); n != "" {
				return n, nil
			}
		}
	case *ast.CompositeLit:
		if n := typeIdent(x.Type); n != "" {
			return n, nil
		}
	case *ast.CallExpr:
		fn := typeIdent(x.Fun)
		if fn == "" {
			break
		}
		for _, f := range files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Recv != nil || fd.Name.Name != fn || fd.Type.Results == nil ||
					len(fd.Type.Results.List) == 0 {
					continue
				}
				switch r := fd.Type.Results.List[0].Type.(type) {
				case *ast.StarExpr:
					if id, ok := r.X.(*ast.Ident); ok {
						return id.Name, nil
					}
				case *ast.Ident:
					return r.Name, nil
				}
			}
		}
	}
	return "", fmt.Errorf("cannot name the extension type of a spec element (%T)", e)
}

// typeIDs renders the parrot once and pairs each extension object with the wire type it wrote, so
// the names read from the source can be turned into numbers without a hand-kept table. An object that
// writes nothing (a padding extension that declines to pad) has no place in the hello and is skipped.
func typeIDs(id *utls.ClientHelloID, sni string) (map[string][]uint16, error) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	u := utls.UClient(c1, &utls.Config{ServerName: sni, InsecureSkipVerify: true, SessionTicketsDisabled: true}, *id)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("BuildHandshakeState: %w", err)
	}
	ch, err := ParseClientHello(u.HandshakeState.Hello.Raw)
	if err != nil {
		return nil, err
	}
	var objs []utls.TLSExtension
	for _, e := range u.Extensions {
		if e.Len() > 0 {
			objs = append(objs, e)
		}
	}
	if len(objs) != len(ch.Extensions) {
		return nil, fmt.Errorf("%d extension objects write bytes, the hello carries %d", len(objs), len(ch.Extensions))
	}
	out := map[string][]uint16{}
	for i, e := range objs {
		t := reflect.TypeOf(e)
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		out[t.Name()] = append(out[t.Name()], ch.Extensions[i].Type)
	}
	return out, nil
}

// typeIdent is the name an identifier or a package-qualified one ends in: SNIExtension for both
// SNIExtension, as uTLS writes it inside its own package, and utls.SNIExtension, as the quic-go
// fork writes it from outside.
func typeIdent(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}
