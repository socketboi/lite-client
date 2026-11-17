package main

import (
	"math/rand"
	"testing"
)

// The map lineMap builds has to be a longest common subsequence: every kept line equal to the one it
// is kept as, the kept lines in order, and as many of them as the longest one there is — which a
// dynamic programme over small inputs says independently.
func TestLineMapIsALongestCommonSubsequence(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	alpha := []string{"a", "b", "c", "d"}
	for round := 0; round < 3000; round++ {
		a := make([]string, r.Intn(14))
		b := make([]string, r.Intn(14))
		for i := range a {
			a[i] = alpha[r.Intn(len(alpha))]
		}
		for i := range b {
			b[i] = alpha[r.Intn(len(alpha))]
		}
		m := lineMap(a, b)
		kept, last := 0, 0
		for i := 1; i <= len(a); i++ {
			if m[i] == 0 {
				continue
			}
			if m[i] <= last || m[i] > len(b) || a[i-1] != b[m[i]-1] {
				t.Fatalf("a=%v b=%v: line %d kept as %d after %d", a, b, i, m[i], last)
			}
			last = m[i]
			kept++
		}
		if want := lcs(a, b); kept != want {
			t.Fatalf("a=%v b=%v: kept %d lines, the longest common subsequence has %d", a, b, kept, want)
		}
	}
}

func lcs(a, b []string) int {
	dp := make([][]int, len(a)+1)
	for i := range dp {
		dp[i] = make([]int, len(b)+1)
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			switch {
			case a[i-1] == b[j-1]:
				dp[i][j] = dp[i-1][j-1] + 1
			case dp[i-1][j] >= dp[i][j-1]:
				dp[i][j] = dp[i-1][j]
			default:
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	return dp[len(a)][len(b)]
}

// A citation moves only when every line it names survived and they are still one run.
func TestRemapNums(t *testing.T) {
	a := []string{"p", "q", "r", "s", "t", "u"}
	b := []string{"new", "p", "q", "r", "X", "t", "u"}
	m := lineMap(a, b)
	cases := []struct {
		in, out string
		ok      bool
	}{
		{"1-3", "2-4", true},
		{"2", "3", true},
		{"5-6, 1", "6-7, 2", true},
		{"3-5", "", false}, // line 4 ("s") was replaced
		{"4", "", false},
		{"9", "", false}, // past the end
	}
	for _, c := range cases {
		got, ok := remapNums(c.in, m)
		if ok != c.ok || (ok && got != c.out) {
			t.Errorf("remapNums(%q) = %q, %v; want %q, %v", c.in, got, ok, c.out, c.ok)
		}
	}
}
