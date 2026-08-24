//go:build unix

package netopen

import (
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixPacketConnOneShotDoesNotReadParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recv.sock")
	laddr := &net.UnixAddr{Name: path, Net: "unixgram"}
	parent, err := net.ListenUnixgram("unixgram", laddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })

	peerPath := filepath.Join(dir, "peer.sock")
	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: peerPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	otherPath := filepath.Join(dir, "other.sock")
	other, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: otherPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })

	if _, err := peer.WriteToUnix([]byte("first"), laddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, addr, err := parent.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}

	child := &unixPacketConn{
		c:      parent,
		peer:   addr,
		first:  append([]byte(nil), buf[:n]...),
		shared: true,
	}

	if _, err := other.WriteToUnix([]byte("second"), laddr); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, 16)
	n, err = child.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != "first" {
		t.Fatalf("first read=%q", got[:n])
	}
	n, err = child.Read(got)
	if n != 0 || err != io.EOF {
		t.Fatalf("second child read n=%d err=%v want EOF", n, err)
	}

	_ = parent.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = parent.ReadFromUnix(got)
	if err != nil {
		t.Fatalf("parent lost the second datagram: %v", err)
	}
	if string(got[:n]) != "second" {
		t.Fatalf("parent read=%q want second", got[:n])
	}
}

func TestUnixPacketConnSetReadDeadlineDoesNotPoisonParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recv.sock")
	laddr := &net.UnixAddr{Name: path, Net: "unixgram"}
	parent, err := net.ListenUnixgram("unixgram", laddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })

	child := &unixPacketConn{c: parent, first: []byte("pkt"), shared: true}
	if err := child.SetReadDeadline(time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(dir, "peer.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := peer.WriteToUnix([]byte("keep"), laddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, _, err := parent.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("parent read after child deadline: %v", err)
	}
	if string(buf[:n]) != "keep" {
		t.Fatalf("got %q", buf[:n])
	}
}
