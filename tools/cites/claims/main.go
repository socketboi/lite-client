// Command claims checks that a citation into vendor/ points at the lines that hold what the comment
// around it says is there.
//
// tools/cites/check.sh proves an address is an address: the file exists and the line is inside it.
// It says in so many words that it does not check the claim — "a citation can point at a real line
// that says something else entirely". Its first run found about a hundred and fifty of those in
// this tree (2026-09-24): the empty-certificate refusal cited thirteen lines above where uTLS keeps
// it, every function of the BBR port a few lines off and one of them onto bandwidthForPacer, which
// the port has as well, a pacer function cited in the wrong file, fetch.c's readLoop handlers each
// on its neighbour, the active connection ID limit on quic-go's SERVER constructor. None of them
// was caught by anything, because every one was an address.
//
// So this checks the parts of a claim a machine can read without understanding it. Every example
// below is one it found; they are spelled out rather than written as citations, so that this
// comment is not itself something to check.
//
//  1. WHAT THE COMMENT QUOTES. Text in backticks, text in double quotes, and the lines of a code
//     block indented inside a comment, from the stretch of the paragraph before the citation. A quote
//     that is code — anything but a bare name — has to be inside the cited lines. It is held to the
//     citation only if the cited file contains it somewhere: have_vers is ours, and a paraphrase in
//     quotes says nothing about where the file keeps its lines. The match ignores case and runs of
//     white space and drops comment markers on the vendored side, so a quote of a Go comment the file
//     wraps over two lines still matches. An ellipsis splits a quote into pieces, each of which must
//     be there.
//
//  2. WHICH FUNCTION IT NAMES. A function the stretch names — a Go name with a hump or Type.Method, a
//     C name of words joined by underscores — that the cited file defines exactly once: of the lines
//     the citation gives in that file, some have to lie inside it or call it. This is what sees a
//     citation with no quote at all: "readServerParameters wants EncryptedExtensions" with a range
//     that began sixteen lines before readServerParameters does.
//
//  3. WHERE THE RANGE LIES. A range that begins inside one Go declaration and ends inside another,
//     leaving code of either outside, is a number that moved. Beginning at a declaration line rather
//     than its doc comment, beginning on the closing brace of the one before, or ending in the doc
//     comment of the next cuts nothing.
//
//  4. A NUMBER ON THE LINE. A citation in a comment that trails a line of code cites the line that
//     holds the number the code uses: a define of 2.885 with the gain constant's line beside it, when
//     2.885 is on the line after. Numbers of fewer than three digits are left alone — every file has
//     them everywhere.
//
//  5. THE FUNCTION BELOW. A comment that makes exactly one claim and stands over a C function that
//     ports a Go one — hybbr_update_recovery_state for updateRecoveryState — has to touch that Go
//     function, unless the comment names another one itself.
//
// A LIST OF CITATIONS IS ONE CLAIM: numbers joined by commas or "and" back the sentence before them
// together, so a quote passes when it is in any of them. A quote that FOLLOWS its citation — "the
// transport is chosen at this line: <quote>" — lands in the stretch of the next citation, so the
// citations just before the stretch count as well.
//
// WHICH FILE. A path under vendor/ names itself. A shorter path or a bare file name is looked for
// inside the vendor tree of the last full citation in the same comment, and in the whole of vendor/
// only when that leaves exactly one file. A bare number after a colon means the file of the
// citation before it in the same comment. A GOROOT/src citation puts what follows it in that comment
// in the toolchain: runtime's table dot go next to runtime's map dot go is not Xray's sudoku table,
// which is the only table dot go under vendor/ and which a search of vendor/ happily returns. A
// citation broken across two lines of a comment is read as one. A patch is prose up to its first
// diff and C comments after it. What stays ambiguous is counted, not guessed.
//
// WHAT THIS DOES NOT SEE: a citation with nothing near it to hold — no quote the file has, no name
// the file defines, no number, no function below — which is still more than half of them; and
// GOROOT/src citations, which name a toolchain rather than a tree in this repository, and not
// always the same toolchain. Those are left to the citation audit and to whoever reads them.
//
//	cd tools/cites/claims && go run . [-v] [path...]    (paths relative to the repository root)
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ---- vendored files ----

// A vendored file, normalised for matching: each line trimmed, lower-cased, comment markers dropped,
// runs of white space collapsed.
type vfile struct {
	lines  []string
	joined string
	starts []int               // byte offset of each line in joined
	funcs  map[string][]extent // Go functions by name, doc comment included
	decls  []decl              // every top-level declaration, in order
}

type extent struct{ a, b int }

// A top-level declaration: where its doc comment starts, where its code starts, where it ends.
type decl struct{ doc, code, end int }

var vcache = map[string]*vfile{}

var vendorCommentRe = regexp.MustCompile(`^\s*(//+|/\*+|\*+/?|#+)\s?`)

func load(path string) *vfile {
	if f, ok := vcache[path]; ok {
		return f
	}
	b, err := os.ReadFile(path)
	if err != nil {
		vcache[path] = nil
		return nil
	}
	raw := strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n")
	f := &vfile{lines: make([]string, len(raw)), starts: make([]int, len(raw))}
	var sb strings.Builder
	for i, l := range raw {
		f.lines[i] = norm(vendorCommentRe.ReplaceAllString(l, ""))
		f.starts[i] = sb.Len()
		sb.WriteString(f.lines[i])
		sb.WriteByte(' ')
	}
	f.joined = sb.String()
	if strings.HasSuffix(path, ".go") {
		f.funcs, f.decls = goFuncs(path, b)
	} else if strings.HasSuffix(path, ".c") {
		f.funcs = cFuncs(raw)
	}
	vcache[path] = f
	return f
}

func goFuncs(path string, src []byte) (map[string][]extent, []decl) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, nil
	}
	out := map[string][]extent{}
	var decls []decl
	for _, d := range file.Decls {
		if gd, ok := d.(*ast.GenDecl); ok {
			from := gd.Pos()
			if gd.Doc != nil {
				from = gd.Doc.Pos()
			}
			decls = append(decls, decl{fset.Position(from).Line, fset.Position(gd.Pos()).Line, fset.Position(gd.End()).Line})
		}
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		from := fd.Pos()
		if fd.Doc != nil {
			from = fd.Doc.Pos()
		}
		e := extent{fset.Position(from).Line, fset.Position(fd.End()).Line}
		decls = append(decls, decl{e.a, fset.Position(fd.Pos()).Line, e.b})
		// Go names are case-sensitive, and so is this: "Body.Close" in prose is the interface method,
		// not the Close of the unexported type body.
		k := fd.Name.Name
		out[k] = append(out[k], e)
		if fd.Recv != nil && len(fd.Recv.List) == 1 {
			if t := recvType(fd.Recv.List[0].Type); t != "" {
				k := t + "." + fd.Name.Name
				out[k] = append(out[k], e)
			}
		}
	}
	return out, decls
}

// A C function's head at the start of a line, with its type on the same line or alone on the line
// above — and not a prototype, a typedef or a statement.
var cHeadRe = regexp.MustCompile(`^(?:(?:static|inline|extern|const|unsigned|signed|struct)\s+)*(?:[A-Za-z_]\w*[\s*]+)?([A-Za-z_]\w*)\s*\(`)

var cKeyword = map[string]bool{"if": true, "for": true, "while": true, "switch": true, "return": true, "sizeof": true}

// The functions a vendored C file defines, from the head to the closing brace in the first column,
// with the comment directly above included. Only as much of C as the vendored libraries write:
// ngtcp2, nghttp3, mbedTLS and the rest start a definition's head at the start of a line and put
// its closing brace alone in the first column.
func cFuncs(raw []string) map[string][]extent {
	out := map[string][]extent{}
	for i := 0; i < len(raw); i++ {
		l := raw[i]
		if l == "" || strings.IndexByte(" \t#/*}", l[0]) >= 0 || strings.HasPrefix(l, "typedef") {
			continue
		}
		m := cHeadRe.FindStringSubmatch(l)
		if m == nil || cKeyword[m[1]] {
			continue
		}
		// The body opens before a ';' ends the head as a prototype.
		open := -1
		for j := i; j < len(raw) && j < i+30; j++ {
			t := strings.TrimSpace(raw[j])
			if strings.Contains(t, "{") {
				open = j
				break
			}
			if strings.HasSuffix(t, ";") {
				break
			}
		}
		if open < 0 {
			continue
		}
		end := -1
		for j := open; j < len(raw); j++ {
			if strings.TrimRight(raw[j], " \t") == "}" {
				end = j
				break
			}
		}
		if end < 0 {
			continue
		}
		start := i
		if strings.HasPrefix(l, m[1]) && i > 0 && raw[i-1] != "" && !strings.ContainsAny(raw[i-1], ";{}(") {
			start = i - 1 // "static int" alone on the line above
		}
		if start > 0 && strings.HasSuffix(strings.TrimSpace(raw[start-1]), "*/") {
			for k := start - 1; k >= 0; k-- {
				if strings.HasPrefix(strings.TrimSpace(raw[k]), "/*") {
					start = k
					break
				}
			}
		}
		out[m[1]] = append(out[m[1]], extent{start + 1, end + 1})
		i = end
	}
	return out
}

func recvType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvType(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvType(t.X)
	case *ast.IndexListExpr:
		return recvType(t.X)
	}
	return ""
}

var spaceRe = regexp.MustCompile(`\s+`)

func norm(s string) string {
	return strings.ToLower(strings.TrimSpace(spaceRe.ReplaceAllString(s, " ")))
}

// The text of lines [a, b] (1-based, inclusive).
func (f *vfile) span(a, b int) string {
	if a < 1 {
		a = 1
	}
	if b > len(f.lines) {
		b = len(f.lines)
	}
	if a > b {
		return ""
	}
	return f.joined[f.starts[a-1] : f.starts[b-1]+len(f.lines[b-1])]
}

// The top-level declaration line n is in, if any.
func (f *vfile) declAt(n int) *decl {
	for i := range f.decls {
		if f.decls[i].doc <= n && n <= f.decls[i].end {
			return &f.decls[i]
		}
	}
	return nil
}

var closingRe = regexp.MustCompile(`^[)\]}\s,;]*$`)

// Whether lines [a, b] hold nothing but closing brackets.
func (f *vfile) closing(a, b int) bool {
	for n := a; n <= b && n <= len(f.lines); n++ {
		if !closingRe.MatchString(f.lines[n-1]) {
			return false
		}
	}
	return true
}

// Lines on which |piece| begins.
func (f *vfile) where(piece string) []int {
	var out []int
	for from := 0; ; {
		k := strings.Index(f.joined[from:], piece)
		if k < 0 {
			return out
		}
		at := from + k
		n := sort.Search(len(f.starts), func(x int) bool { return f.starts[x] > at })
		if len(out) == 0 || out[len(out)-1] != n {
			out = append(out, n)
		}
		from = at + 1
	}
}

// ---- the vendor index ----

var vindex []string

func indexVendor() {
	filepath.WalkDir("vendor", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		vindex = append(vindex, filepath.ToSlash(p))
		return nil
	})
}

func candidates(name, within string) []string {
	var out []string
	for _, p := range vindex {
		if (p == name || strings.HasSuffix(p, "/"+name)) && strings.HasPrefix(p, within) {
			out = append(out, p)
		}
	}
	return out
}

func treeOf(p string) string {
	parts := strings.SplitN(p, "/", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[0] + "/" + parts[1] + "/"
}

// ---- reading our files as comment text ----

type line struct {
	no      int
	text    string // the comment text, its marker and one space removed
	comment bool   // whether the line carries comment text at all
	code    string // what is outside comments on the line, for C and Go
}

// C and Go: only what is inside comments. Go raw strings are skipped so that a "//" in one is not
// read as a comment.
func commentLines(raw []string, goRaw bool) []line {
	out := make([]line, len(raw))
	inBlock, inRaw := false, false
	for i, l := range raw {
		out[i].no = i + 1
		var b, code strings.Builder
		has := false
		j := 0
		if inBlock {
			has = true
			k := 0
			for k < len(l) && (l[k] == ' ' || l[k] == '\t') {
				k++
			}
			if k < len(l) && l[k] == '*' && !(k+1 < len(l) && l[k+1] == '/') {
				k++
				if k < len(l) && l[k] == ' ' {
					k++
				}
				j = k
			}
		}
		for j < len(l) {
			c := l[j]
			switch {
			case inBlock:
				if c == '*' && j+1 < len(l) && l[j+1] == '/' {
					inBlock = false
					j += 2
					continue
				}
				b.WriteByte(c)
				j++
			case inRaw:
				if c == '`' {
					inRaw = false
				}
				j++
			case c == '/' && j+1 < len(l) && l[j+1] == '*':
				inBlock, has = true, true
				j += 2
				for j < len(l) && l[j] == '*' {
					j++
				}
				if j < len(l) && l[j] == ' ' {
					j++
				}
			case c == '/' && j+1 < len(l) && l[j+1] == '/':
				has = true
				j += 2
				for j < len(l) && l[j] == '/' {
					j++
				}
				if j < len(l) && l[j] == ' ' {
					j++
				}
				b.WriteString(l[j:])
				j = len(l)
			case c == '"' || c == '\'':
				q := c
				from := j
				j++
				for j < len(l) && l[j] != q {
					if l[j] == '\\' {
						j++
					}
					j++
				}
				j++
				code.WriteString(l[from:min(j, len(l))])
			case goRaw && c == '`':
				inRaw = true
				j++
			default:
				code.WriteByte(c)
				j++
			}
		}
		out[i].text = b.String()
		out[i].comment = has
		out[i].code = code.String()
	}
	return out
}

var hashRe = regexp.MustCompile(`^\s*#+ ?`)

// Makefile, shell, markdown and the rest: every line, a leading "#" removed.
func proseLines(raw []string) []line {
	out := make([]line, len(raw))
	for i, l := range raw {
		out[i] = line{no: i + 1, text: hashRe.ReplaceAllString(l, ""), comment: strings.TrimSpace(l) != ""}
	}
	return out
}

// A patch: the message before the first diff is prose; after it, the added and context lines are C
// with their diff marker taken off, and only their comments are read.
func patchLines(raw []string) []line {
	// The diff begins at "diff --git" when the patch has one, and at the first "---"/"+++" pair when
	// it does not — and several here do not.
	first := len(raw)
	for i, l := range raw {
		if strings.HasPrefix(l, "diff ") ||
			strings.HasPrefix(l, "--- ") && i+1 < len(raw) && strings.HasPrefix(raw[i+1], "+++ ") {
			first = i
			break
		}
	}
	head := make([]string, len(raw))
	body := make([]string, len(raw))
	for i, l := range raw {
		switch {
		case i < first:
			head[i] = l
		case strings.HasPrefix(l, "+++") || strings.HasPrefix(l, "---") || strings.HasPrefix(l, "@@") ||
			strings.HasPrefix(l, "diff ") || strings.HasPrefix(l, "index ") || strings.HasPrefix(l, "-"):
		case strings.HasPrefix(l, "+") || strings.HasPrefix(l, " "):
			body[i] = l[1:]
		}
	}
	out := proseLines(head)
	// Hunk by hunk: a hunk's context can stop inside a comment, and read straight on, every line of
	// the next hunk up to its first "*/" became that comment's text — code included, so a `} else {`
	// of the next hunk was taken for a quote (0014's initialPaddingLen, 2026-09-26).
	for s := first; s < len(raw); {
		e := s + 1
		for e < len(raw) && !strings.HasPrefix(raw[e], "@@") && !strings.HasPrefix(raw[e], "diff ") {
			e++
		}
		for k, l := range commentLines(body[s:e], false) {
			l.no = s + k + 1
			out[s+k] = l
		}
		s = e
	}
	return out
}

// ---- citations ----

type interval struct{ a, b int }

type cite struct {
	at, end int // byte offsets in the paragraph
	numsAt  int // where the number list starts and ends in the paragraph, for -remap
	numsEnd int
	name    string
	nums    []interval
	line    int
	text    string
	file    string
	ours    bool
	unres   string
}

var (
	// A number list may run on with ", 381", and the numbers may start on the next line.
	numsPat = `\n?(\d+(?:[-,] ?\d+)*)`
	fullRe  = regexp.MustCompile(`(?:GOROOT/src/)?[A-Za-z0-9_][A-Za-z0-9_./+-]*\.(?:go|c|h|cc|hpp|rs|py|proto|s|in):` + numsPat)
	shortRe = regexp.MustCompile(`(^|[\s(,;\x60])(:(\d+(?:[-,] ?\d+)*))`)
	glueRe  = regexp.MustCompile(`^[\s,;:\x60()]*(?:(?:and|or|и|или)[\s,;:\x60()]*)?$`)
)

func parseNums(s string) []interval {
	var out []interval
	for _, part := range strings.Split(strings.ReplaceAll(s, " ", ""), ",") {
		ab := strings.SplitN(part, "-", 2)
		a, err := strconv.Atoi(ab[0])
		if err != nil {
			continue
		}
		b := a
		if len(ab) == 2 {
			if v, err := strconv.Atoi(ab[1]); err == nil {
				b = v
			}
		}
		out = append(out, interval{a, b})
	}
	return out
}

// ---- quotes ----

var (
	tickRe  = regexp.MustCompile("`([^`]{1,240})`")
	quoteRe = regexp.MustCompile(`"([^"\n]{3,240})"|“([^”]{3,240})”`)
	ellRe   = regexp.MustCompile(`\.\.\.|…`)

	// One plain word — "silent", "else", "Roots", "quic-go" — is prose far more often than it is a
	// quote, and when it is a quote it is too common to say where anything is.
	wordRe = regexp.MustCompile(`^[A-Za-z][a-z-]*$`)
	// A bare name — `signalWrite`, `Defragger.Feed`, `maxHeaderListSize()` — names a thing rather
	// than quoting a line of it, and the citation after it usually points INTO the thing. Names are
	// held to the function check, not to the quote check.
	nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\(\))?$`)
	// A name worth looking for in prose: a hump inside it, or Type.Method — or, for C, words joined
	// by underscores, the way ngtcp2 and mbedTLS name their functions.
	humpRe = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*(?:[a-z0-9][A-Z]|\.[A-Za-z_]|[a-z0-9]_[a-z])[A-Za-z0-9_.]*`)
)

type quote struct {
	text   string
	pieces []string
}

func mkQuote(s string) (quote, bool) {
	s = strings.TrimSpace(spaceRe.ReplaceAllString(s, " "))
	if wordRe.MatchString(s) || nameRe.MatchString(s) {
		return quote{}, false
	}
	parts := ellRe.Split(s, -1)
	var pieces []string
	for _, p := range parts {
		if len(parts) > 1 {
			// "ReceivedAck(..., rcvTime)": the elided arguments leave punctuation on the edges.
			p = strings.Trim(p, " ,;:()[]{}")
		}
		p = norm(p)
		if len(p) >= 2 && strings.IndexFunc(p, func(r rune) bool {
			return r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		}) >= 0 {
			pieces = append(pieces, p)
		}
	}
	if len(pieces) == 0 {
		return quote{}, false
	}
	return quote{text: s, pieces: pieces}, true
}

func (q quote) in(text string) bool {
	for _, p := range q.pieces {
		if !strings.Contains(text, p) {
			return false
		}
	}
	return true
}

func quotesOf(stretch string) []quote {
	var out []quote
	seen := map[string]bool{}
	add := func(s string) {
		if q, ok := mkQuote(s); ok && !seen[q.text] {
			seen[q.text] = true
			out = append(out, q)
		}
	}
	for _, m := range tickRe.FindAllStringSubmatch(stretch, -1) {
		add(m[1])
	}
	for _, m := range quoteRe.FindAllStringSubmatch(tickRe.ReplaceAllString(stretch, " "), -1) {
		add(m[1] + m[2])
	}
	for _, l := range strings.Split(stretch, "\n") {
		if strings.HasPrefix(l, "    ") || strings.HasPrefix(l, "\t") {
			l = strings.TrimRight(strings.TrimSpace(l), "( ")
			if !strings.ContainsAny(l, "`\"") {
				add(l)
			}
		}
	}
	return out
}

// ---- the walk ----

type finding struct {
	where string
	cites []cite
	lines []string
}

var (
	verbose              = flag.Bool("v", false, "print every held citation, not only the misplaced")
	checked, held, named int
	anchored             int // citations in a stretch that something held
	unres                = map[string]int{}
	findings             []finding
	oks                  []string
)

func scan(path string) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 4<<20 || strings.IndexByte(string(b[:min(len(b), 8000)]), 0) >= 0 {
		return
	}
	raw := strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n")
	if rawOf != nil {
		rawOf[path] = raw
	}
	var ls []line
	switch {
	case strings.HasSuffix(path, ".c") || strings.HasSuffix(path, ".h"):
		ls = commentLines(raw, false)
	case strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".go.in"):
		ls = commentLines(raw, true)
	case strings.HasSuffix(path, ".patch"):
		ls = patchLines(raw)
	default:
		ls = proseLines(raw)
	}
	for i := 0; i < len(ls); {
		if !ls[i].comment {
			i++
			continue
		}
		j := i
		for j < len(ls) && ls[j].comment {
			j++
		}
		// The C function the comment stands over, if the next code is a definition of one.
		follow := ""
		if j < len(ls) {
			next := ls[j].code
			if j+1 < len(ls) {
				next += " " + ls[j+1].code
			}
			if m := cFuncRe.FindStringSubmatch(next); m != nil {
				follow = m[1]
			}
		}
		block(path, ls[i:j], follow)
		i = j
	}
}

// A C function definition's head: a return type, the name, the opening parenthesis — and not a
// statement, a declaration of a variable, or a typedef.
var cFuncRe = regexp.MustCompile(`^\s*(?:static\s+)?(?:inline\s+)?(?:const\s+)?(?:unsigned\s+)?(?:struct\s+)?[A-Za-z_]\w*[\s*]+([A-Za-z_]\w*)\s*\(`)

type pending struct {
	g, prev []cite
	stretch string
}

// The tree a GOROOT citation leaves the comment in.
const goroot = "GOROOT/"

func block(path string, ls []line, follow string) {
	var all []pending
	codeOf := map[int]string{}
	for _, l := range ls {
		codeOf[l.no] = l.code
	}
	last, lastOurs, lastTree := "", false, ""
	for p := 0; p < len(ls); {
		if strings.TrimSpace(ls[p].text) == "" {
			p++
			continue
		}
		q := p
		for q < len(ls) && strings.TrimSpace(ls[q].text) != "" {
			q++
		}
		var sb strings.Builder
		starts := make([]int, 0, q-p)
		for k := p; k < q; k++ {
			starts = append(starts, sb.Len())
			sb.WriteString(ls[k].text)
			sb.WriteByte('\n')
		}
		para := sb.String()
		lineAt := func(off int) int {
			return ls[p+sort.Search(len(starts), func(x int) bool { return starts[x] > off })-1].no
		}

		var cs []cite
		for _, m := range fullRe.FindAllStringSubmatchIndex(para, -1) {
			whole := para[m[0]:m[1]]
			name := whole[:strings.LastIndex(whole[:m[2]-m[0]], ":")]
			cs = append(cs, cite{at: m[0], end: m[1], numsAt: m[2], numsEnd: m[3], name: name,
				nums: parseNums(para[m[2]:m[3]]), line: lineAt(m[0]), text: strings.ReplaceAll(whole, "\n", "")})
		}
		for _, m := range shortRe.FindAllStringSubmatchIndex(para, -1) {
			at, dup := m[4], false
			for _, c := range cs {
				if at >= c.at && at < c.end {
					dup = true
				}
			}
			if !dup {
				cs = append(cs, cite{at: at, end: m[5], numsAt: m[6], numsEnd: m[7], nums: parseNums(para[m[6]:m[7]]),
					line: lineAt(at), text: para[at:m[5]]})
			}
		}
		sort.Slice(cs, func(a, b int) bool { return cs[a].at < cs[b].at })

		for k := range cs {
			c := &cs[k]
			switch {
			case c.name == "" && lastTree == goroot:
				c.unres = "GOROOT"
			case c.name == "":
				if lastOurs || last == "" {
					c.ours, c.unres = lastOurs, "a short form with no vendored file before it"
				} else {
					c.file = last
				}
			case strings.HasPrefix(c.name, "GOROOT/"):
				// And what follows it in the same comment is the toolchain's too: a bare "table dot go"
				// right after runtime's map dot go is runtime's table, not the one table dot go under
				// vendor/, which is Xray's sudoku table, whatever a search of vendor/ turns up.
				c.unres, lastTree, last, lastOurs = "GOROOT", goroot, "", false
			case lastTree == goroot && !strings.HasPrefix(c.name, "vendor/") && !strings.Contains(c.name, "/"):
				c.unres = "GOROOT"
			case strings.HasPrefix(c.name, "vendor/"):
				if _, err := os.Stat(c.name); err == nil {
					c.file, lastTree = c.name, treeOf(c.name)
				} else {
					c.unres = "no such file"
				}
			case strings.HasPrefix(c.name, "src/") || strings.HasPrefix(c.name, "test/") ||
				strings.HasPrefix(c.name, "tools/") || strings.HasPrefix(c.name, "patches/") || ourFile(c.name):
				c.ours = true
			default:
				cands := candidates(c.name, lastTree)
				if len(cands) != 1 {
					cands = candidates(c.name, "vendor/")
				}
				switch len(cands) {
				case 1:
					c.file = cands[0]
				case 0:
					c.unres = "not in vendor"
				default:
					c.unres = "ambiguous"
				}
			}
			if c.file != "" {
				last, lastOurs = c.file, false
			} else if c.ours {
				last, lastOurs = "", true
			}
			if c.file == "" && !c.ours {
				unres[c.unres]++
			}
		}
		if onCites != nil {
			onCites(path, ls[p:q], starts, para, cs)
		}

		// Groups: citations with nothing but punctuation or "and" between them.
		var groups [][]cite
		for k := range cs {
			if k > 0 && glueRe.MatchString(para[cs[k-1].end:cs[k].at]) {
				groups[len(groups)-1] = append(groups[len(groups)-1], cs[k])
			} else {
				groups = append(groups, []cite{cs[k]})
			}
		}
		prevEnd := 0
		var prev []cite
		for _, g := range groups {
			all = append(all, pending{g, prev, para[prevEnd:g[0].at]})
			prevEnd = g[len(g)-1].end
			prev = g
		}
		p = q
	}
	// The function below the comment is what the comment is about only when the comment makes one
	// claim; a long comment over a function cites whatever it discusses.
	if len(all) != 1 {
		follow = ""
	}
	for _, pd := range all {
		judge(path, pd.g, pd.prev, pd.stretch, follow, codeOf)
	}
}

var ourNames map[string]bool

func ourFile(name string) bool {
	return ourNames[name] && len(candidates(name, "vendor/")) == 0
}

func inRange(cs []cite, q quote) bool {
	for _, c := range cs {
		if c.file == "" {
			continue
		}
		f := load(c.file)
		if f == nil {
			continue
		}
		for _, iv := range c.nums {
			if q.in(f.span(iv.a, iv.b)) {
				return true
			}
		}
	}
	return false
}

// A number on a line of code: a hex literal, a decimal fraction, or three digits and more. Shorter
// integers — 4, 8, 32 — are in every file many times and say nothing about where.
var numRe = regexp.MustCompile(`\b(0[xX][0-9a-fA-F]+|\d+\.\d+|\d{3,})\b`)

// Whether |text| holds |lit| as a whole number, not as the digits of a longer one.
func hasNum(text, lit string) bool {
	for from := 0; ; {
		k := strings.Index(text[from:], lit)
		if k < 0 {
			return false
		}
		at := from + k
		end := at + len(lit)
		isPart := func(b byte) bool {
			return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b == '_' || b == '.'
		}
		if (at == 0 || !isPart(text[at-1])) && (end == len(text) || !isPart(text[end]) ||
			text[end] == '.' && (end+1 == len(text) || text[end+1] < '0' || text[end+1] > '9')) {
			return true
		}
		from = at + 1
	}
}

// A C name as the Go name it ports: hybbr_update_recovery_state → updaterecoverystate, tried with
// its leading words dropped one at a time, longest first, and matched without case against the Go
// functions of the file. Only a single match counts.
func goNameFor(f *vfile, cname string) (string, extent, bool) {
	words := strings.Split(strings.ToLower(cname), "_")
	lower := map[string][]string{}
	for n := range f.funcs {
		if !strings.Contains(n, ".") {
			lower[strings.ToLower(n)] = append(lower[strings.ToLower(n)], n)
		}
	}
	for k := 0; k < len(words); k++ {
		cand := strings.Join(words[k:], "")
		if len(cand) < 6 {
			break
		}
		if ns := lower[cand]; len(ns) == 1 && len(f.funcs[ns[0]]) == 1 {
			return ns[0], f.funcs[ns[0]][0], true
		}
	}
	return "", extent{}, false
}

func judge(path string, g, prev []cite, stretch, follow string, codeOf map[int]string) {
	var live []cite
	for _, c := range g {
		if c.file != "" && load(c.file) != nil {
			live = append(live, c)
		}
	}
	if len(live) == 0 {
		return
	}
	checked += len(live)
	var bad []string

	// 1. Quotes that the cited files hold must be in the cited lines.
	quoted := false
	for _, q := range quotesOf(stretch) {
		inFile := false
		for _, c := range live {
			if q.in(load(c.file).joined) {
				inFile = true
			}
		}
		if !inFile {
			continue
		}
		quoted = true
		if inRange(live, q) || inRange(prev, q) {
			continue
		}
		var at []string
		for _, c := range live {
			if w := load(c.file).where(q.pieces[0]); len(w) > 0 {
				at = append(at, fmt.Sprintf("%s:%v", c.file, trim(w)))
			}
		}
		bad = append(bad, fmt.Sprintf("quotes %q, which is at %s", q.text, strings.Join(at, " ")))
	}

	// 2. Functions the stretch names and a cited Go file defines once: of the lines the group cites
	// in that file, some have to touch one of them — lie inside it, or call it: a sentence that names
	// readUint24LengthPrefixed and cites the unmarshal that calls it is telling a reader where it is
	// used. Only SOME: "writeRecordLocked" followed by two numbers, the second of them uTLS's c.write,
	// backs the next writer down with that number, and the sentence names it without a hump.
	names := map[string]bool{}
	for _, m := range humpRe.FindAllString(stretch, -1) {
		names[strings.TrimRight(m, ".")] = true
	}
	namedAny := false
	namedIn := map[string]bool{}
	byFile := map[string][]interval{}
	var order []string
	for _, c := range live {
		if _, ok := byFile[c.file]; !ok {
			order = append(order, c.file)
		}
		byFile[c.file] = append(byFile[c.file], c.nums...)
	}
	for _, file := range order {
		f := load(file)
		var exts []extent
		var which []string
		for n := range names {
			if e := f.funcs[n]; len(e) == 1 {
				exts = append(exts, e[0])
				which = append(which, n)
			}
		}
		if len(exts) == 0 {
			continue
		}
		namedAny, namedIn[file] = true, true
		touches := false
		for _, iv := range byFile[file] {
			for _, e := range exts {
				if iv.a <= e.b && iv.b >= e.a {
					touches = true
				}
			}
			text := f.span(iv.a, iv.b)
			for _, n := range which {
				if strings.Contains(text, strings.ToLower(n[strings.LastIndex(n, ".")+1:])) {
					touches = true
				}
			}
		}
		if !touches {
			sort.Strings(which)
			var at, ivs []string
			for _, n := range which {
				e := f.funcs[n][0]
				at = append(at, fmt.Sprintf("%s %d-%d", n, e.a, e.b))
			}
			for _, iv := range byFile[file] {
				ivs = append(ivs, fmt.Sprintf("%d-%d", iv.a, iv.b))
			}
			bad = append(bad, fmt.Sprintf("%s:%s touches none of the functions it names: %s",
				file, strings.Join(ivs, ","), strings.Join(at, ", ")))
		}
	}

	// 4. A citation in a comment that trails a line of code — HYBBR_DEFAULT_HIGH_GAIN 2.885 with
	// bbr_sender's line 37 beside it, when 2.885 is on line 38 — cites the line that holds the number
	// the code uses. When the file holds that number at all, the cited lines must hold it.
	for _, c := range live {
		code := codeOf[c.line]
		if strings.TrimSpace(code) == "" {
			continue
		}
		f := load(c.file)
		for _, lit := range numRe.FindAllString(code, -1) {
			lit = strings.ToLower(lit)
			if !hasNum(f.joined, lit) {
				continue
			}
			quoted = true
			in := false
			for _, iv := range c.nums {
				if hasNum(f.span(iv.a, iv.b), lit) {
					in = true
				}
			}
			if !in {
				var at []string
				for _, n := range f.where(lit) {
					if hasNum(f.lines[n-1], lit) {
						at = append(at, strconv.Itoa(n))
					}
				}
				bad = append(bad, fmt.Sprintf("%s: the code on this line uses %s, which is at %s",
					c.text, lit, strings.Join(at[:min(len(at), 6)], ",")))
			}
		}
	}

	// 5. A comment that makes one claim and stands over a C function that ports a Go one: the cited
	// lines must touch that Go function. bbr_sender's lines 660-672 over hybbr_get_min_rtt, when
	// getMinRtt is at 674-689 and 660-672 is bandwidthForPacer, was one of these.
	if follow != "" {
		for _, c := range live {
			// What the comment names outranks what the function below it is called: "OnCongestionEventEx
			// (…:538-638)" over hybbr_on_congestion_event means the Ex one.
			if namedIn[c.file] {
				continue
			}
			f := load(c.file)
			n, e, ok := goNameFor(f, follow)
			if !ok {
				continue
			}
			namedAny = true
			touches := false
			for _, iv := range c.nums {
				if iv.a <= e.b && iv.b >= e.a {
					touches = true
				}
			}
			if !touches {
				bad = append(bad, fmt.Sprintf("%s stands over %s, which ports %s at %d-%d", c.text, follow, n, e.a, e.b))
			}
		}
	}

	// 3. A range that begins inside one declaration and ends inside another, taking neither whole,
	// is a number that moved: nobody means "the last lines of this function and the first of the
	// next". "readServerParameters wants EncryptedExtensions (…:669-706)" began sixteen lines
	// before the function it names and was never held by anything else here.
	for _, c := range live {
		f := load(c.file)
		for _, iv := range c.nums {
			x, y := f.declAt(iv.a), f.declAt(iv.b)
			if x == nil || y == nil || *x == *y {
				continue
			}
			// Cut means code left outside: the range begins past the head of x with more than closing
			// braces still to come, or ends inside the code of y before its end. Beginning at a
			// declaration line rather than its doc comment, or ending in the doc comment of the next
			// one, cuts nothing.
			cutX := iv.a > x.code && !f.closing(iv.a, x.end)
			cutY := iv.b >= y.code && iv.b < y.end
			if cutX || cutY {
				bad = append(bad, fmt.Sprintf("%s:%d-%d begins in the declaration at %d-%d and ends in the one at %d-%d",
					c.file, iv.a, iv.b, x.doc, x.end, y.doc, y.end))
			}
		}
	}

	if quoted {
		held++
	}
	if namedAny {
		named++
	}
	if quoted || namedAny {
		anchored += len(live)
	}
	if len(bad) > 0 {
		findings = append(findings, finding{where: fmt.Sprintf("%s:%d", path, g[0].line), cites: live, lines: bad})
	} else if *verbose && (quoted || namedAny) {
		oks = append(oks, fmt.Sprintf("%s:%d %s", path, g[0].line, live[0].text))
	}
}

func trim(v []int) []int {
	if len(v) > 6 {
		return v[:6]
	}
	return v
}

func main() {
	flag.Parse()
	if len(remapTrees) > 0 {
		remapMain()
		return
	}
	if err := os.Chdir("../../.."); err != nil {
		fmt.Println("  FAIL  cannot reach the repository root:", err)
		os.Exit(2)
	}
	where := flag.Args()
	if len(where) == 0 {
		where = []string{"src", "patches", "Makefile", "README.md", "docs/BUILD.md", "docs/DESIGN.md", "test", "tools"}
	}
	if _, err := os.Stat("vendor"); err != nil {
		fmt.Println("  ok    no vendor/ tree to check citations against")
		return
	}
	indexVendor()
	ourNames = map[string]bool{}
	for _, w := range []string{"src", "test", "tools"} {
		filepath.WalkDir(w, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				ourNames[d.Name()] = true
			}
			return nil
		})
	}
	for _, w := range where {
		filepath.WalkDir(w, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" || d.Name() == ".goroot-x" {
					return filepath.SkipDir
				}
				return nil
			}
			scan(filepath.ToSlash(p))
			return nil
		})
	}

	for _, s := range oks {
		fmt.Println("  held  " + s)
	}
	for _, fd := range findings {
		var cs []string
		for _, c := range fd.cites {
			cs = append(cs, c.text)
		}
		fmt.Printf("  FAIL  %s  %s  (%s)\n", fd.where, strings.Join(cs, ", "), fd.cites[0].file)
		for _, l := range fd.lines {
			fmt.Println("          " + l)
		}
	}
	var ks []string
	for k := range unres {
		ks = append(ks, fmt.Sprintf("%s %d", k, unres[k]))
	}
	sort.Strings(ks)
	status := "ok   "
	if len(findings) > 0 {
		status = "FAIL "
	}
	fmt.Printf("  %s %d citations into vendor/ resolved, %d of them held by something near them (%d stretches by a quote or a number, %d by a function); %d misplaced (not resolved: %s)\n",
		status, checked, anchored, held, named, len(findings), strings.Join(ks, ", "))
	if len(findings) > 0 {
		os.Exit(1)
	}
}
