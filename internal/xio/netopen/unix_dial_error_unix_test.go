//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUnixConnectBindFailureNamesBindPath(t *testing.T) {
	dest := unixSocketTestPath(t, "dest.sock")
	bindPath := unixSocketTestPath(t, "bind.sock")
	startUnixStreamPeer(t, dest)
	startUnixStreamPeer(t, bindPath)
	spec := parse.Spec{
		Type:    "UNIX-CONNECT",
		Params:  []string{dest},
		Options: []parse.Option{{Name: "bind", Value: bindPath, Has: true}},
	}
	_, err := openUnixConnect(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "bind") || !strings.Contains(err.Error(), bindPath) {
		t.Fatalf("error=%v", err)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("error=%v want EADDRINUSE", err)
	}
}

func TestUnixSendtoBindFailureNamesBindPath(t *testing.T) {
	remote := unixSocketTestPath(t, "remote.sock")
	bindPath := unixSocketTestPath(t, "bind.sock")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: bindPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	spec, err := parse.ParseSpec("UNIX-SENDTO:" + remote + ",bind=" + bindPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = openUnixSendto(context.Background(), mustAddr(t, spec), xio.ModeWrite, nil)
	if err == nil || !strings.Contains(err.Error(), "bind") || !strings.Contains(err.Error(), bindPath) {
		t.Fatalf("error=%v", err)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("error=%v want EADDRINUSE", err)
	}
}

func TestUnixGenericClientReachesDatagramPeer(t *testing.T) {
	path := unixSocketTestPath(t, "peer.sock")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	spec, err := parse.ParseSpec("UNIX:" + path)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixConnect(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
}
