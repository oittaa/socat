//go:build unix

package xio

import "testing"

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
			want:   "exec 10<&3 11<&4 4<&10 5>&11 3>&- 10>&- 11>&-",
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
