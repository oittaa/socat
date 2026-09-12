//go:build linux

package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"golang.org/x/sys/unix"
)

func TestDrainRecvErrEmptyQueueLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
		t.Fatal(err)
	}
	drainRecvErrQueue(fd, &Global{Log: logx.New()})
}

func TestHandleIPRecvErrTruncatedCmsgLinux(t *testing.T) {
	g := &Global{Log: logx.New(), Peer: Peer{SessionVars: map[string]string{}}}
	handleIPRecvErrCmsg([]byte{1, 2, 3}, g)
	if len(g.Peer.SessionVars) != 0 {
		t.Fatalf("truncated cmsg set env %v", g.Peer.SessionVars)
	}
}
