//go:build linux || darwin

package xio

import (
	"strconv"
	"testing"
)

func TestExtraSources(t *testing.T) {
	in, out := extraSources(ModeRDWR, true)
	if in != "3" || out != "3" {
		t.Fatalf("socket RDWR %s %s", in, out)
	}
	in, out = extraSources(ModeRDWR, false)
	if in != "3" || out != "4" {
		t.Fatalf("pipes RDWR %s %s", in, out)
	}
	in, out = extraSources(ModeRead, false)
	if in != "" || out != "3" {
		t.Fatalf("pipes read %s %s", in, out)
	}
	in, out = extraSources(ModeWrite, true)
	if in != "3" || out != "" {
		t.Fatalf("socket write %s %s", in, out)
	}
}

func TestUnusedFDNumbersAreSingleDigit(t *testing.T) {
	for a := 3; a <= 9; a++ {
		for b := 3; b <= 9; b++ {
			for c := 3; c <= 9; c++ {
				for d := 3; d <= 9; d++ {
					x, y := unusedFDNumbers(strconv.Itoa(a), strconv.Itoa(b), strconv.Itoa(c), strconv.Itoa(d))
					n1, err1 := strconv.Atoi(x)
					n2, err2 := strconv.Atoi(y)
					if err1 != nil || err2 != nil || n1 < 3 || n1 > 9 || n2 < 3 || n2 > 9 || n1 == n2 {
						t.Fatalf("avoid %d,%d,%d,%d -> %q %q", a, b, c, d, x, y)
					}
					taken := map[int]bool{0: true, 1: true, 2: true, a: true, b: true, c: true, d: true}
					if taken[n1] || taken[n2] {
						t.Fatalf("collision avoid %d,%d,%d,%d -> %d %d", a, b, c, d, n1, n2)
					}
				}
			}
		}
	}
}
