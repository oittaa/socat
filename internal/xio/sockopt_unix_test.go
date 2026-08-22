//go:build unix

package xio

import (
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplySocketTimeosUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	apply := func(specText string, rcvWant, sndWant time.Duration) {
		t.Helper()
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplySocketTimeos(fd, spec); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name string
			opt  int
			want time.Duration
		}{
			{name: "receive", opt: soRcvtimeo, want: rcvWant},
			{name: "send", opt: soSndtimeo, want: sndWant},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tv, err := unix.GetsockoptTimeval(fd, solSocket, tc.opt)
				if err != nil {
					t.Fatal(err)
				}
				if got := time.Duration(unix.TimevalToNsec(*tv)); got != tc.want {
					t.Fatalf("timeout=%v want %v", got, tc.want)
				}
			})
		}
	}

	apply("UDP:127.0.0.1:9,rcvtimeo=1.25,sndtimeo=2.5", 1250*time.Millisecond, 2500*time.Millisecond)
	apply("UDP:127.0.0.1:9,rcvtimeo=0,sndtimeo=0", 0, 0)
}

func TestTimevalFromSpecRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"-1", "banana", "NaN", "1e100"} {
		if _, err := timevalFromSpec(value); err == nil {
			t.Errorf("timevalFromSpec(%q) succeeded", value)
		}
	}
}
