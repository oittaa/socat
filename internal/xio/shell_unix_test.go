//go:build unix

package xio

import (
	"regexp"
	"strconv"
	"testing"
)

func TestChildFDRedirectPrefix(t *testing.T) {
	tests := []struct {
		name          string
		inSrc, outSrc string
		fdin, fdout   string
		stderr        bool
		want          string
	}{
		{
			name:   "socket-fdin3-fdout4",
			inSrc:  "3",
			outSrc: "3",
			fdin:   "3",
			fdout:  "4",
			want:   "exec 4>&3",
		},
		{
			name:   "socket-fdin5-fdout6-close3",
			inSrc:  "3",
			outSrc: "3",
			fdin:   "5",
			fdout:  "6",
			want:   "exec 5<&3 6>&3 3>&-",
		},
		{
			name:   "socket-mode-read-fdout4",
			outSrc: "3",
			fdout:  "4",
			want:   "exec 4>&3 3>&-",
		},
		{
			name:  "socket-mode-write-fdin3",
			inSrc: "3",
			fdin:  "3",
			want:  "exec",
		},
		{
			name:   "socket-stderr-fdout4",
			inSrc:  "3",
			outSrc: "3",
			fdin:   "3",
			fdout:  "4",
			stderr: true,
			want:   "exec 4>&3 2>&4",
		},
		{
			name:   "mode-write-stderr-default-fdo",
			inSrc:  "3",
			fdin:   "3",
			stderr: true,
			want:   "exec 2>&1",
		},
		{
			name:   "pipes-fdin3-fdout4-already-mapped",
			inSrc:  "3",
			outSrc: "4",
			fdin:   "3",
			fdout:  "4",
			want:   "exec",
		},
		{
			name:   "pipes-overlap-in-on-out-src",
			inSrc:  "3",
			outSrc: "4",
			fdin:   "4",
			fdout:  "5",
			want:   "exec 6<&3 7<&4 4<&6 5>&7 3>&- 6>&- 7>&-",
		},
		{
			name:   "pipes-overlap-swap",
			inSrc:  "3",
			outSrc: "4",
			fdin:   "4",
			fdout:  "3",
			want:   "exec 5<&3 6<&4 4<&5 3>&6 5>&- 6>&-",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := childFDRedirectPrefix(tc.inSrc, tc.outSrc, tc.fdin, tc.fdout, tc.stderr)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

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

func TestChildFDRedirectPrefixDashSafe(t *testing.T) {
	unsafe := regexp.MustCompile(`[0-9]{2,}(?:<&|>&)`)
	for fdin := 0; fdin <= 9; fdin++ {
		for fdout := 0; fdout <= 9; fdout++ {
			in := strconv.Itoa(fdin)
			out := strconv.Itoa(fdout)
			for _, tc := range []struct {
				inSrc, outSrc string
			}{
				{"3", "3"},
				{"3", "4"},
				{"3", ""},
				{"", "3"},
			} {
				got := childFDRedirectPrefix(tc.inSrc, tc.outSrc, in, out, false)
				if unsafe.MatchString(got) {
					t.Fatalf("dash-unsafe prefix %q fdin=%s fdout=%s src=%s/%s", got, in, out, tc.inSrc, tc.outSrc)
				}
			}
		}
	}
}
