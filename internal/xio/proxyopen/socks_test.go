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
	if got := socks5AuthMethods(false); len(got) != 1 || got[0] != 0 {
		t.Fatalf("no credentials: %v want [0]", got)
	}
	if got := socks5AuthMethods(true); len(got) != 2 || got[0] != 0 || got[1] != 2 {
		t.Fatalf("credentials: %v want [0 2] (classic 05 02 00 02)", got)
	}
}

func TestSOCKS5CredentialsClassicFallback(t *testing.T) {
	user, pass, offer := socks5Credentials(parse.Spec{})
	if user != "" || pass != "" || offer {
		t.Fatalf("no options: user=%q pass=%q offer=%v", user, pass, offer)
	}
	s, err := parse.ParseSpec("SOCKS5:127.0.0.1:127.0.0.1:80,sockspass=p")
	if err != nil {
		t.Fatal(err)
	}
	user, pass, offer = socks5Credentials(s)
	if user != "anonymous" || pass != "p" || !offer {
		t.Fatalf("pass only: user=%q pass=%q offer=%v want anonymous/p/true", user, pass, offer)
	}
	s, err = parse.ParseSpec("SOCKS5:127.0.0.1:127.0.0.1:80,socksuser=u")
	if err != nil {
		t.Fatal(err)
	}
	user, pass, offer = socks5Credentials(s)
	if user != "u" || pass != "" || !offer {
		t.Fatalf("user only: user=%q pass=%q offer=%v want u/empty/true", user, pass, offer)
	}
	s, err = parse.ParseSpec("SOCKS5:127.0.0.1:127.0.0.1:80,socksuser=nobody,sockspass=s3cr3t")
	if err != nil {
		t.Fatal(err)
	}
	user, pass, offer = socks5Credentials(s)
	if user != "nobody" || pass != "s3cr3t" || !offer {
		t.Fatalf("both: user=%q pass=%q offer=%v", user, pass, offer)
	}
}

func TestSOCKS5ConnectWithCredentialsOffersClassicHello(t *testing.T) {
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
	if len(hello) != 4 || hello[0] != 5 || hello[1] != 2 || hello[2] != 0 || hello[3] != 2 {
		t.Fatalf("hello=%x want 05 02 00 02 (classic no-auth and username/password)", hello)
	}
}

// mockSOCKS5AuthEcho implements classic socks5server-auth.sh: require greeting
// 05 02 00 02, then username/password, then CONNECT/BIND + echo.
func mockSOCKS5AuthEcho(t *testing.T, ln net.Listener, wantUser, wantPass string) {
	t.Helper()
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Errorf("hello hdr: %v", err)
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		t.Errorf("hello methods: %v", err)
		return
	}
	if hdr[0] != 5 || hdr[1] != 2 || len(methods) != 2 || methods[0] != 0 || methods[1] != 2 {
		t.Errorf("bad hello %x%x want 05 02 00 02", hdr, methods)
		return
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return
	}
	authHdr := make([]byte, 2)
	if _, err := io.ReadFull(c, authHdr); err != nil {
		t.Errorf("auth hdr: %v", err)
		return
	}
	if authHdr[0] != 1 {
		t.Errorf("auth ver %d", authHdr[0])
		return
	}
	user := make([]byte, int(authHdr[1]))
	if _, err := io.ReadFull(c, user); err != nil {
		t.Errorf("auth user: %v", err)
		return
	}
	var plen [1]byte
	if _, err := io.ReadFull(c, plen[:]); err != nil {
		t.Errorf("auth plen: %v", err)
		return
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(c, pass); err != nil {
		t.Errorf("auth pass: %v", err)
		return
	}
	if string(user) != wantUser || string(pass) != wantPass {
		t.Errorf("auth %q:%q want %q:%q", user, pass, wantUser, wantPass)
		_, _ = c.Write([]byte{1, 0xff})
		return
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
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

func echoViaSOCKS5Auth(t *testing.T, spec, wantUser, wantPass string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go mockSOCKS5AuthEcho(t, ln, wantUser, wantPass)
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := parse.ParseSpec(spec + ",socksport=" + strconv.Itoa(port) + ",pf=ip4")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o, err := openSOCKS5Connect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
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

func TestSOCKS5UserPassClassic604(t *testing.T) {
	// Classic test.sh SOCKS5_USER_PASS: socksuser=nobody,sockspass=s3cr3t
	// against socks5server-auth.sh, which requires greeting 05 02 00 02.
	echoViaSOCKS5Auth(t, "SOCKS5-CONNECT:127.0.0.1:127.0.0.1:80,socksuser=nobody,sockspass=s3cr3t", "nobody", "s3cr3t")
}

func TestSOCKS5PassOnlyFallsBackToAnonymous(t *testing.T) {
	echoViaSOCKS5Auth(t, "SOCKS5-CONNECT:127.0.0.1:127.0.0.1:80,sockspass=p", "anonymous", "p")
}

func TestSOCKS5CredentialsAcceptsServerNoAuth(t *testing.T) {
	// Classic still offers method 0 with credentials, so a no-auth server works.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		methods := make([]byte, int(hdr[1]))
		if _, err := io.ReadFull(c, methods); err != nil {
			return
		}
		if _, err := c.Write([]byte{5, 0}); err != nil {
			return
		}
		req := make([]byte, 10)
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		if _, err := c.Write([]byte{5, 0, 0, 1, 0x10, 0, 0x1f, 0x64, 0x1f, 0x64}); err != nil {
			return
		}
		_, _ = io.Copy(c, c)
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := parse.ParseSpec("SOCKS5-CONNECT:127.0.0.1:127.0.0.1:80,socksuser=u,sockspass=p,socksport=" + strconv.Itoa(port) + ",pf=ip4")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o, err := openSOCKS5Connect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
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
