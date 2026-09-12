//go:build linux || darwin

package netopen

import (
	"context"
	"io"
	"net"
	"os"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func startUnixStreamPeer(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
}

func openBoundUnixConnect(t *testing.T, listen, bind string, extra ...parse.Option) *xio.Opened {
	t.Helper()
	opts := append([]parse.Option{{Name: "bind", Value: bind, Has: true}}, extra...)
	spec := parse.Spec{
		Type:    "UNIX-CONNECT",
		Params:  []string{listen},
		Options: opts,
	}
	o, err := openUnixConnect(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestUnixConnectBindUnlinksOnClose(t *testing.T) {
	listen := unixSocketTestPath(t, "listen.sock")
	bind := unixSocketTestPath(t, "client.sock")
	startUnixStreamPeer(t, listen)

	o := openBoundUnixConnect(t, listen, bind)
	if _, err := os.Lstat(bind); err != nil {
		t.Fatalf("CONNECT bind path missing after open: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(bind); !os.IsNotExist(err) {
		t.Fatalf("CONNECT bind path survived Close: %v", err)
	}
	if xio.RegisteredUnlinkCount() != 0 {
		t.Fatal("Close left a signal-exit unlink registration")
	}
}

func TestUnixConnectBindUnlinksOnSignalSweep(t *testing.T) {
	listen := unixSocketTestPath(t, "listen.sock")
	bind := unixSocketTestPath(t, "client.sock")
	startUnixStreamPeer(t, listen)

	o := openBoundUnixConnect(t, listen, bind)
	t.Cleanup(func() { _ = o.Close() })
	if _, err := os.Lstat(bind); err != nil {
		t.Fatalf("CONNECT bind path missing after open: %v", err)
	}
	if xio.RegisteredUnlinkCount() == 0 {
		t.Fatal("CONNECT bind path was not registered for signal-exit unlink")
	}
	xio.UnlinkRegisteredPaths()
	if _, err := os.Lstat(bind); !os.IsNotExist(err) {
		t.Fatalf("CONNECT bind path survived signal sweep: %v", err)
	}
}

func TestUnixConnectBindUnlinkCloseZeroKeepsPath(t *testing.T) {
	listen := unixSocketTestPath(t, "listen.sock")
	bind := unixSocketTestPath(t, "client.sock")
	startUnixStreamPeer(t, listen)

	o := openBoundUnixConnect(t, listen, bind, parse.Option{Name: "unlink-close", Value: "0", Has: true})
	if xio.RegisteredUnlinkCount() != 0 {
		t.Fatal("unlink-close=0 registered a signal-exit unlink")
	}
	xio.UnlinkRegisteredPaths()
	if _, err := os.Lstat(bind); err != nil {
		t.Fatalf("unlink-close=0 bind path was removed on signal sweep: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(bind); err != nil {
		t.Fatalf("unlink-close=0 bind path was removed on close: %v", err)
	}
}
