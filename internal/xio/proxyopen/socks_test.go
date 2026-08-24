package proxyopen

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
)

// mockSOCKS5Echo implements socks5server-echo.sh: no-auth, CONNECT or BIND
// to 127.0.0.1:80, then echo remaining bytes.
func mockSOCKS5Echo(t *testing.T, ln net.Listener) {
	t.Helper()
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	hello := make([]byte, 3)
	if _, err := io.ReadFull(c, hello); err != nil {
		t.Errorf("hello: %v", err)
		return
	}
	if hello[0] != 5 || hello[1] != 1 || hello[2] != 0 {
		t.Errorf("bad hello %x", hello)
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 10)
	if _, err := io.ReadFull(c, req); err != nil {
		t.Errorf("req: %v", err)
		return
	}
	if req[0] != 5 || (req[1] != 1 && req[1] != 2) || req[3] != 1 {
		t.Errorf("bad req %x", req)
		return
	}
	// First reply (CONNECT success or BIND listen).
	if _, err := c.Write([]byte{5, 0, 0, 1, 0x10, 0, 0x1f, 0x64, 0x1f, 0x64}); err != nil {
		return
	}
	if req[1] == 2 {
		if _, err := c.Write([]byte{5, 0, 0, 1, 0x10, 0xff, 0x1f, 0x64, 0x23, 0x28}); err != nil {
			return
		}
	}
	_, _ = io.Copy(c, c)
}

func echoViaSOCKS5(t *testing.T, spec string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go mockSOCKS5Echo(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := parse.ParseSpec(spec + ",socksport=" + strconv.Itoa(port) + ",pf=ip4")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var o *xio.Opened
	if s.Type == "SOCKS5-LISTEN" || s.Type == "SOCKS5-BIND" {
		o, err = openSOCKS5Listen(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	} else {
		o, err = openSOCKS5Connect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	payload := []byte("socks5-ok\n")
	if _, err := o.Stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(o.Stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("got %q", buf)
	}
}

func TestSOCKS5ConnectEcho(t *testing.T) {
	echoViaSOCKS5(t, "SOCKS5-CONNECT:127.0.0.1:127.0.0.1:80")
}

func TestSOCKS5ListenEcho(t *testing.T) {
	echoViaSOCKS5(t, "SOCKS5-LISTEN:127.0.0.1:127.0.0.1:80")
}

func TestSOCKSUserEnvironmentFallback(t *testing.T) {
	t.Setenv("LOGNAME", "log-user")
	t.Setenv("USER", "fallback-user")
	if got := socksUser(parse.Spec{}); got != "log-user" {
		t.Fatalf("LOGNAME fallback=%q", got)
	}
	t.Setenv("LOGNAME", "")
	if got := socksUser(parse.Spec{}); got != "fallback-user" {
		t.Fatalf("USER fallback=%q", got)
	}
	s := parse.Spec{Options: []parse.Option{{Name: "socksuser", Value: "option-user", Has: true}}}
	if got := socksUser(s); got != "option-user" {
		t.Fatalf("option=%q", got)
	}
	t.Setenv("USER", "")
	if got := socksUser(parse.Spec{}); got != "anonymous" {
		t.Fatalf("default=%q", got)
	}
}

func TestSOCKS5AuthMethods(t *testing.T) {
	if got := socks5AuthMethods("", ""); len(got) != 1 || got[0] != 0 {
		t.Fatalf("no credentials: %v want [0]", got)
	}
	if got := socks5AuthMethods("user", ""); len(got) != 1 || got[0] != 2 {
		t.Fatalf("user only: %v want [2]", got)
	}
	if got := socks5AuthMethods("user", "pass"); len(got) != 1 || got[0] != 2 {
		t.Fatalf("user and pass: %v want [2]", got)
	}
	if got := socks5AuthMethods("", "pass"); len(got) != 1 || got[0] != 2 {
		t.Fatalf("pass only: %v want [2]", got)
	}
}

func TestSOCKS5ConnectWithCredentialsDoesNotOfferNoAuth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	helloCh := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			helloCh <- nil
			return
		}
		defer func() { _ = c.Close() }()
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(c, hdr); err != nil {
			helloCh <- nil
			return
		}
		methods := make([]byte, int(hdr[1]))
		if _, err := io.ReadFull(c, methods); err != nil {
			helloCh <- nil
			return
		}
		helloCh <- append(append([]byte{}, hdr...), methods...)
		_, _ = c.Write([]byte{5, 0xff})
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := parse.ParseSpec("SOCKS5-CONNECT:127.0.0.1:127.0.0.1:80,socksuser=u,sockspass=p,socksport=" + strconv.Itoa(port) + ",pf=ip4")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = openSOCKS5Connect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	hello := <-helloCh
	if len(hello) != 3 || hello[0] != 5 || hello[1] != 1 || hello[2] != 2 {
		t.Fatalf("hello=%x want 05 01 02 (username/password only)", hello)
	}
}
