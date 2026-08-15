//go:build linux

package netopen

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func skipIfNoSCTP(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("no kernel SCTP: %v", err)
	}
	unix.Close(fd)
}

func TestSCTP4Echo(t *testing.T) {
	skipIfNoSCTP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ln, err := listenSCTP(ctx, "sctp4", "127.0.0.1", "0", parse.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr type %T", ln.Addr())
	}
	port := ta.Port
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- "accept:" + err.Error()
			return
		}
		defer c.Close()
		b, err := io.ReadAll(c)
		if err != nil {
			got <- "read:" + err.Error()
			return
		}
		got <- string(b)
	}()

	g := &xio.Global{Log: logx.New()}
	c, err := dialSCTPAll(ctx, "sctp4", "127.0.0.1", strconv.Itoa(port), parse.Spec{}, g, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c, "hello-sctp"); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		t.Fatal("timeout")
	case s := <-got:
		if s != "hello-sctp" {
			t.Fatalf("got %q", s)
		}
	}
}

func TestSCTPOpenChannelListenTimeout(t *testing.T) {
	skipIfNoSCTP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel("SCTP4-LISTEN:0,reuseaddr,bind=127.0.0.1,accept-timeout=0.05")
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{Log: logx.New()}
	_, err = xio.OpenChannel(ctx, ch, xio.ModeRDWR, g)
	if err != xio.ErrAcceptTimeout {
		t.Fatalf("want accept timeout, got %v", err)
	}
}

func TestSCTPServiceNameHTTP(t *testing.T) {
	n, err := xio.ResolvePortNum("sctp4", "http")
	if err != nil {
		t.Fatal(err)
	}
	if n != 80 {
		t.Fatalf("http=%d", n)
	}
}
