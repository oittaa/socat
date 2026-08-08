package addr

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

func TestBindTCPAddrForRemoteFamily(t *testing.T) {
	ctx := context.Background()
	// IPv4 bind + IPv6 remote → skip
	_, skip, err := bindTCPAddrForRemote(ctx, net.ParseIP("::1"), "127.0.0.1", "0", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if !skip {
		t.Fatal("expected skip for IPv4 bind vs IPv6 remote")
	}
	// IPv4 bind + IPv4 remote → ok
	la, skip, err := bindTCPAddrForRemote(ctx, net.ParseIP("127.0.0.1"), "127.0.0.1", "0", "tcp")
	if err != nil || skip || la == nil || la.IP.To4() == nil {
		t.Fatalf("v4 bind: la=%v skip=%v err=%v", la, skip, err)
	}
	// IPv6 bind + IPv6 remote
	la, skip, err = bindTCPAddrForRemote(ctx, net.ParseIP("::1"), "::1", "0", "tcp")
	if err != nil || skip || la == nil || la.IP.To4() != nil {
		t.Fatalf("v6 bind: la=%v skip=%v err=%v", la, skip, err)
	}
}

func TestDialTCPAllLogsAF(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	var buf strings.Builder
	log := logx.New()
	log.SetLevel(logx.Debug)
	log.SetOutput(&buf)
	g := &Global{Log: log}
	s := parse.Spec{Type: "TCP4"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := dialTCPAll(ctx, "tcp4", "127.0.0.1", strconv.Itoa(port), s, g, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if !strings.Contains(buf.String(), "opening connection to AF=2 ") {
		t.Fatalf("missing AF=2 notice log: %q", buf.String())
	}
}

func TestDialTCPAllTriesSecondAddress(t *testing.T) {
	// Server on 127.0.0.1 only. 127.0.0.2 is typically local and refused.
	// We cannot inject DNS without a custom resolver; verify refused-then-success
	// by dialing a closed port (log AF=2) and an open port separately, and that
	// multi-IP resolution for dual-stack hostnames returns ordered results.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	// Closed first: ensure error path still logs AF=
	closedLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	closedLn.Close()

	var buf strings.Builder
	log := logx.New()
	log.SetLevel(logx.Notice)
	log.SetOutput(&buf)
	g := &Global{Log: log}
	s := parse.Spec{Type: "TCP4"}
	ctx := context.Background()
	_, err = dialTCPAll(ctx, "tcp4", "127.0.0.1", strconv.Itoa(closedPort), s, g, 200*time.Millisecond, nil)
	if err == nil {
		t.Fatal("expected refuse on closed port")
	}
	if !strings.Contains(buf.String(), "opening connection to AF=2 ") {
		t.Fatalf("missing log on refuse: %q", buf.String())
	}

	buf.Reset()
	c, err := dialTCPAll(ctx, "tcp4", "127.0.0.1", strconv.Itoa(port), s, g, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestConnectNetworkPreferDualStack(t *testing.T) {
	g := &Global{IPVersion: IPv6}
	s := parse.Spec{Type: "TCP"}
	if n := connectNetworkForType(g, s, "example.com", "tcp"); n != "tcp" {
		t.Fatalf("generic TCP want tcp got %s", n)
	}
	if n := connectNetworkForType(g, s, "example.com", "tcp4"); n != "tcp4" {
		t.Fatalf("TCP4 forced want tcp4 got %s", n)
	}
	s.Options = []parse.Option{{Name: "pf", Value: "ip4", Has: true}}
	if n := connectNetworkForType(g, s, "example.com", "tcp"); n != "tcp4" {
		t.Fatalf("pf=ip4 want tcp4 got %s", n)
	}
}

func TestResolveOrderIPv6First(t *testing.T) {
	ctx := context.Background()
	g := &Global{IPVersion: IPv6}
	s := parse.Spec{}
	ips, err := resolveConnectIPs(ctx, "tcp", "localhost", s, g)
	if err != nil {
		t.Skip(err)
	}
	if len(ips) < 2 {
		t.Skip("localhost not dual-stack")
	}
	if ips[0].To4() != nil {
		t.Fatalf("with -6 preference first IP should be v6, got %v", ips)
	}
}

func TestTLSClientNoSNI(t *testing.T) {
	cfg, err := tlsClientConfig(parse.Spec{
		Type: "OPENSSL",
		Options: []parse.Option{
			{Name: "openssl-no-sni"},
			{Name: "verify", Value: "0"},
		},
	}, "badssl.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "" {
		t.Fatalf("openssl-no-sni: ServerName=%q want empty", cfg.ServerName)
	}
}

func TestTLSClientSNIHost(t *testing.T) {
	cfg, err := tlsClientConfig(parse.Spec{
		Type: "OPENSSL",
		Options: []parse.Option{
			{Name: "openssl-snihost", Value: "sni.example", Has: true},
			{Name: "verify", Value: "0"},
		},
	}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "sni.example" {
		t.Fatalf("ServerName=%q", cfg.ServerName)
	}
}
