// -remap: carry the line numbers of citations over to a newer version of a vendored tree.
//
// When vendor/<tree> moves to a newer upstream revision, every "file.go:N" into it names a line of
// the OLD file. Most of those lines survive the upgrade and have only moved; a few have changed, and
// those are exactly the places where the reference now behaves differently from what the comment
// beside the citation says — the list worth reading before anything else.
//
//	cd tools/cites/claims && go run . -remap vendor/hysteria/=/path/to/new/hysteria [-remap ...] [-write]
//
// Citations are found and resolved exactly as the check finds them (full paths, short ":N" forms,
// bare file names), against the tree as it is — the OLD one, which must still be in vendor/. Each
// cited file is compared line by line with its counterpart under the new root (a Myers diff), and
//
//	moved     every cited line survives, still contiguous: the numbers are rewritten (with -write)
//	same      nothing moved
//	reshaped  the first and last cited lines survived but something between them changed: the
//	          ends are rewritten and the citation is printed, since what the comment says may not
//	          be true of the new block
//	changed   a cited end was edited or removed: printed with the old text, left alone
//	gone      the file is not in the new tree: printed, left alone
//
// A number list that runs onto the next line of the comment is reported and not rewritten.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type remapFlag []string

func (r *remapFlag) String() string     { return strings.Join(*r, ",") }
func (r *remapFlag) Set(v string) error { *r = append(*r, v); return nil }

var (
	remapTrees remapFlag
	remapWrite = flag.Bool("write", false, "with -remap: rewrite the moved citations in place")
	rawOf      map[string][]string
	onCites    func(path string, ls []line, starts []int, para string, cs []cite)
)

func init() {
	flag.Var(&remapTrees, "remap", "vendor/<tree>/=<new root>: map citations into <tree> onto the new root")
}

type remapPair struct{ old, new string }

// One replacement in one of our files: the number list at [col, col+len(old)) on line `no`.
type edit struct {
	no      int
	col     int
	old, nu string
}

var (
	pairs    []remapPair
	lineMaps = map[string][]int{} // old file -> new line for each old line (1-based, 0 = changed)
	gone     = map[string]bool{}
	edits    = map[string][]edit{}
	counts   = map[string]int{}
	reports  []string
)

// Myers' diff reduced to what is needed here: for each line of a, the line of b it is kept as, or 0.
// The trace keeps, for each step d, only the band of diagonals it can have touched, -d-1..d+1.
func lineMap(a, b []string) []int {
	n, m := len(a), len(b)
	max := n + m
	off := max + 1 // v[off+k] is the furthest x on diagonal k, k in -(max+1)..max+1
	v := make([]int, 2*max+3)
	var trace [][]int
	for d := 0; d <= max; d++ {
		// The state before step d, diagonals -d-1..d+1: band[k+d+1] is diagonal k.
		trace = append(trace, append([]int(nil), v[off-d-1:off+d+2]...))
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x, y = x+1, y+1
			}
			v[off+k] = x
			if x >= n && y >= m {
				return backtrack(trace, a, b, d)
			}
		}
	}
	return make([]int, n+1)
}

func backtrack(trace [][]int, a, b []string, d int) []int {
	out := make([]int, len(a)+1)
	x, y := len(a), len(b)
	for ; d > 0; d-- {
		band := trace[d]
		at := func(k int) int { return band[k+d+1] }
		k := x - y
		var pk int
		if k == -d || (k != d && at(k-1) < at(k+1)) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := at(pk)
		py := px - pk
		for x > px && y > py {
			out[x] = y
			x, y = x-1, y-1
		}
		x, y = px, py
	}
	for x > 0 && y > 0 {
		out[x] = y
		x, y = x-1, y-1
	}
	return out
}

func readLines(p string) ([]string, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n"), true
}

// The map for an old vendored file, and whether its tree is one being remapped.
func mapFor(file string) ([]int, bool) {
	for _, pr := range pairs {
		if !strings.HasPrefix(file, pr.old) {
			continue
		}
		if m, ok := lineMaps[file]; ok || gone[file] {
			return m, true
		}
		a, _ := readLines(file)
		b, ok := readLines(filepath.Join(pr.new, strings.TrimPrefix(file, pr.old)))
		if !ok {
			gone[file] = true
			return nil, true
		}
		lineMaps[file] = lineMap(a, b)
		return lineMaps[file], true
	}
	return nil, false
}

// The number list with only the ends of each interval carried over: for a range whose first and last
// lines both survived — a whole function whose body changed — the new ends still bound the same
// block. ok is false when an end did not survive.
func remapEnds(text string, m []int) (string, bool) {
	parts := strings.Split(text, ",")
	for i, part := range parts {
		lead := part[:len(part)-len(strings.TrimLeft(part, " "))]
		ab := strings.SplitN(strings.TrimSpace(part), "-", 2)
		a, err := strconv.Atoi(ab[0])
		if err != nil || a < 1 || a >= len(m) || m[a] == 0 {
			return "", false
		}
		if len(ab) == 1 {
			parts[i] = lead + strconv.Itoa(m[a])
			continue
		}
		b, err := strconv.Atoi(ab[1])
		if err != nil || b <= a || b >= len(m) || m[b] == 0 {
			return "", false
		}
		parts[i] = lead + strconv.Itoa(m[a]) + "-" + strconv.Itoa(m[b])
	}
	return strings.Join(parts, ","), true
}

// The number list with each interval carried over, keeping its separators; ok is false when some
// cited line did not survive or the survivors are no longer contiguous.
func remapNums(text string, m []int) (string, bool) {
	parts := strings.Split(text, ",")
	for i, part := range parts {
		lead := part[:len(part)-len(strings.TrimLeft(part, " "))]
		ab := strings.SplitN(strings.TrimSpace(part), "-", 2)
		a, err := strconv.Atoi(ab[0])
		if err != nil || a < 1 || a >= len(m) {
			return "", false
		}
		b := a
		if len(ab) == 2 {
			if b, err = strconv.Atoi(ab[1]); err != nil || b < a || b >= len(m) {
				return "", false
			}
		}
		for n := a; n <= b; n++ {
			if m[n] == 0 || m[n] != m[a]+(n-a) {
				return "", false
			}
		}
		if a == b {
			parts[i] = lead + strconv.Itoa(m[a])
		} else {
			parts[i] = lead + strconv.Itoa(m[a]) + "-" + strconv.Itoa(m[b])
		}
	}
	return strings.Join(parts, ","), true
}

func remapCites(path string, ls []line, starts []int, para string, cs []cite) {
	for _, c := range cs {
		if c.file == "" {
			continue
		}
		m, ours := mapFor(c.file)
		if !ours {
			continue
		}
		where := fmt.Sprintf("%s:%d %s", path, c.line, strings.TrimSpace(c.text))
		if gone[c.file] {
			counts["gone"]++
			reports = append(reports, "gone     "+where)
			continue
		}
		text := para[c.numsAt:c.numsEnd]
		if strings.Contains(text, "\n") {
			counts["manual"]++
			reports = append(reports, "manual   "+where+"  (the numbers run onto the next line)")
			continue
		}
		nu, ok := remapNums(text, m)
		reshaped := false
		if !ok {
			if nu, ok = remapEnds(text, m); ok {
				reshaped = true
			}
		}
		if !ok || reshaped {
			if reshaped {
				counts["reshaped"]++
			} else {
				counts["changed"]++
			}
			old, _ := readLines(c.file)
			var body []string
			for _, iv := range c.nums {
				for n := iv.a; n <= iv.b && n <= len(old) && len(body) < 12; n++ {
					mark := "  "
					if n < len(m) && m[n] == 0 {
						mark = "- "
					}
					body = append(body, fmt.Sprintf("            %s%d: %s", mark, n, strings.TrimRight(old[n-1], " \t")))
				}
			}
			if !reshaped {
				reports = append(reports, "changed  "+where+"  ("+c.file+")\n"+strings.Join(body, "\n"))
				continue
			}
			// Carried over, and still listed: the block is the same one, what it says may not be.
			reports = append(reports, "reshaped "+where+"  -> "+nu+"  ("+c.file+")\n"+strings.Join(body, "\n"))
		} else if nu == text {
			counts["same"]++
			continue
		} else {
			counts["moved"]++
		}
		// Where the number list sits in the source line: the comment text of that line is a suffix
		// of it, so its column is found by searching the raw line for the text.
		k := sort.Search(len(starts), func(x int) bool { return starts[x] > c.numsAt }) - 1
		off := c.numsAt - starts[k]
		raw := rawOf[path][ls[k].no-1]
		base := strings.Index(raw, ls[k].text)
		if base < 0 || !strings.HasPrefix(raw[base+off:], text) {
			counts["manual"]++
			reports = append(reports, "manual   "+where+"  (cannot place it in the source line)")
			continue
		}
		edits[path] = append(edits[path], edit{no: ls[k].no, col: base + off, old: text, nu: nu})
		if *verbose {
			reports = append(reports, "moved    "+where+"  -> "+nu+"  ("+c.file+")")
		}
	}
}

func remapMain() {
	for _, t := range remapTrees {
		kv := strings.SplitN(t, "=", 2)
		if len(kv) != 2 || !strings.HasPrefix(kv[0], "vendor/") || !strings.HasSuffix(kv[0], "/") {
			fmt.Println("-remap wants vendor/<tree>/=<new root>")
			os.Exit(2)
		}
		abs, err := filepath.Abs(kv[1])
		if err != nil {
			fmt.Println(err)
			os.Exit(2)
		}
		pairs = append(pairs, remapPair{kv[0], abs})
	}
	if err := os.Chdir("../../.."); err != nil {
		fmt.Println("cannot reach the repository root:", err)
		os.Exit(2)
	}
	indexVendor()
	ourNames = map[string]bool{}
	for _, w := range []string{"src", "test", "tools"} {
		filepath.WalkDir(w, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				ourNames[d.Name()] = true
			}
			return nil
		})
	}
	rawOf = map[string][]string{}
	onCites = remapCites
	where := flag.Args()
	if len(where) == 0 {
		where = []string{"src", "patches", "Makefile", "README.md", "docs", "VENDOR.md", "CONCURRENCY.md", "COVERAGE.md",
			"VENDOR-REVERSE.md", "test", "tools", "package", "docker"}
	}
	for _, w := range where {
		filepath.WalkDir(w, func(p string, d os.DirEntry, err error) error {
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
	for _, r := range reports {
		fmt.Println(r)
	}
	fmt.Printf("remap: %d moved, %d same, %d reshaped, %d changed, %d gone, %d manual\n",
		counts["moved"], counts["same"], counts["reshaped"], counts["changed"], counts["gone"], counts["manual"])
	if !*remapWrite {
		return
	}
	// A patch series has to stay consistent with itself: a line one patch adds can be context — or a
	// removed line — in the next, and there it sits inside a comment whose opening the hunk cut off,
	// so it is not read as a citation at all. Whatever an added line became, it becomes wherever
	// the same line appears as context or removal in the series.
	became := map[string]string{} // an added line of a patch, before -> after
	changed := map[string]bool{}
	for path, es := range edits {
		raw := rawOf[path]
		// Right to left within a line, so earlier columns stay valid.
		sort.Slice(es, func(i, j int) bool {
			if es[i].no != es[j].no {
				return es[i].no < es[j].no
			}
			return es[i].col > es[j].col
		})
		before := map[int]string{}
		for _, e := range es {
			l := raw[e.no-1]
			if _, ok := before[e.no]; !ok {
				before[e.no] = l
			}
			raw[e.no-1] = l[:e.col] + e.nu + l[e.col+len(e.old):]
		}
		if strings.HasSuffix(path, ".patch") {
			for no, l := range before {
				if strings.HasPrefix(l, "+") {
					became[l[1:]] = raw[no-1][1:]
				}
			}
		}
		changed[path] = true
	}
	for path, raw := range rawOf {
		if !strings.HasSuffix(path, ".patch") {
			continue
		}
		for i, l := range raw {
			if (strings.HasPrefix(l, " ") || strings.HasPrefix(l, "-")) && !strings.HasPrefix(l, "---") {
				if nu, ok := became[l[1:]]; ok {
					raw[i] = l[:1] + nu
					changed[path] = true
				}
			}
		}
	}
	for path := range changed {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		os.WriteFile(path, []byte(strings.Join(rawOf[path], "\n")), info.Mode())
	}
	fmt.Printf("remap: rewrote %d files\n", len(changed))
}
