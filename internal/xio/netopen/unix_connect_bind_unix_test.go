//go:build linux || darwin

package netopen

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
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
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
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

func TestUnixConnectBindWrapFailureUnlinksPath(t *testing.T) {
	listen := unixSocketTestPath(t, "listen.sock")
	bind := unixSocketTestPath(t, "client.sock")
	startUnixStreamPeer(t, listen)

	spec := parse.Spec{
		Type:   "UNIX-CONNECT",
		Params: []string{listen},
		Options: []parse.Option{
			{Name: "bind", Value: bind, Has: true},
			{Name: "readbytes", Value: "nope", Has: true},
		},
	}
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected invalid readbytes to fail after connect")
	}
	if _, err := os.Lstat(bind); !os.IsNotExist(err) {
		t.Fatalf("CONNECT bind path survived WrapCommon failure: %v", err)
	}
	if xio.RegisteredUnlinkCount() != 0 {
		t.Fatal("WrapCommon failure left a signal-exit unlink registration")
	}
}

func TestUnixConnectBindWrapFailureUnlinkCloseZeroKeepsPath(t *testing.T) {
	listen := unixSocketTestPath(t, "listen.sock")
	bind := unixSocketTestPath(t, "client.sock")
	startUnixStreamPeer(t, listen)

	spec := parse.Spec{
		Type:   "UNIX-CONNECT",
		Params: []string{listen},
		Options: []parse.Option{
			{Name: "bind", Value: bind, Has: true},
			{Name: "unlink-close", Value: "0", Has: true},
			{Name: "readbytes", Value: "nope", Has: true},
		},
	}
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected invalid readbytes to fail after connect")
	}
	if _, err := os.Lstat(bind); err != nil {
		t.Fatalf("unlink-close=0 bind path was removed on WrapCommon failure: %v", err)
	}
}

func TestUnixConnectBindTempnameUnlinksOnClose(t *testing.T) {
	listen := unixSocketTestPath(t, "listen.sock")
	startUnixStreamPeer(t, listen)
	pat := unixSocketTestPath(t, "bind.XXXXXX")
	g := &xio.Global{}
	spec := parse.Spec{
		Type:    "UNIX-CONNECT",
		Params:  []string{listen},
		Options: []parse.Option{{Name: "unix-bind-tempname", Value: pat, Has: true}},
	}
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	if g.SockAddr == "" || g.SockAddr == listen {
		t.Fatalf("tempname bind path unset: SockAddr=%q", g.SockAddr)
	}
	if _, err := os.Lstat(g.SockAddr); err != nil {
		t.Fatalf("tempname bind path missing after open: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(g.SockAddr); !os.IsNotExist(err) {
		t.Fatalf("tempname bind path survived Close: %v", err)
	}
}

func TestUnixSeqpacketConnectBindUnlinksOnClose(t *testing.T) {
	if _, ok := unixSeqpacketNetwork(); !ok {
		t.Skip("SOCK_SEQPACKET is unavailable on this platform")
	}
	listen := unixSocketTestPath(t, "listen.sock")
	bind := unixSocketTestPath(t, "client.sock")
	ln := listenUnixpacket(t, listen)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		uln, ok := ln.(net.Listener)
		if !ok {
			return
		}
		for {
			c, err := uln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()

	o := openBoundUnixConnect(t, listen, bind, parse.Option{
		Name:  "socktype",
		Value: strconv.Itoa(syscall.SOCK_SEQPACKET),
		Has:   true,
	})
	if _, err := os.Lstat(bind); err != nil {
		t.Fatalf("seqpacket CONNECT bind path missing after open: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(bind); !os.IsNotExist(err) {
		t.Fatalf("seqpacket CONNECT bind path survived Close: %v", err)
	}
}

func TestUnixConnectAbstractBindDoesNotRegisterUnlink(t *testing.T) {
	if !xio.FeatureABSTRACT {
		t.Skip("abstract UNIX sockets not enabled")
	}
	peer := "\x00socat-abs-connect-peer"
	bindName := "@socat-abs-connect-bind"
	ln, err := net.Listen("unix", peer)
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

	before := xio.RegisteredUnlinkCount()
	spec := parse.Spec{
		Type:   "UNIX-CONNECT",
		Params: []string{"@socat-abs-connect-peer"},
		Options: []parse.Option{
			{Name: "bind", Value: bindName, Has: true},
		},
	}
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if xio.RegisteredUnlinkCount() != before {
		t.Fatal("abstract CONNECT bind registered a signal-exit unlink")
	}
}
