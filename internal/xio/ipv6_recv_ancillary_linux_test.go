//go:build linux

package xio

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxIPv6BlobIntSetsockoptRejected(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	opts := []struct {
		name string
		opt  int
	}{
		{"IPV6_DSTOPTS", unix.IPV6_DSTOPTS},
		{"IPV6_HOPOPTS", unix.IPV6_HOPOPTS},
		{"IPV6_RTHDR", unix.IPV6_RTHDR},
		{"IPV6_HOPLIMIT", unix.IPV6_HOPLIMIT},
		{"IPV6_PKTINFO", unix.IPV6_PKTINFO},
		{"IPV6_AUTHHDR", unix.IPV6_AUTHHDR},
	}
	for _, o := range opts {
		err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, o.opt, 1)
		if err == nil {
			t.Errorf("%s int setsockopt succeeded; do not classify as an unimplementable blob without implementing it", o.name)
		}
	}
}
