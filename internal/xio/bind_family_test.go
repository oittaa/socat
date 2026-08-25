package xio_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/xio"

	_ "github.com/oittaa/socat/internal/xio/all"
)

func testGlobal() *xio.Global {
	return &xio.Global{BlockSize: 8192, Log: logx.New()}
}

func openSpec(t *testing.T, spec string) (*xio.Opened, error) {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	return xio.OpenSpec(context.Background(), s, xio.ModeRDWR, testGlobal())
}

func skipUnavailableSCTP(t *testing.T, err error) bool {
	t.Helper()
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "protocol not supported") {
		t.Skip(err.Error())
		return true
	}
	return false
}

func TestForcedFamilyBindRejectedAndAccepted(t *testing.T) {
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "")
	cert, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	type tc struct {
		name    string
		spec    string
		wantErr string
		ipv6    bool
		sctp    bool
	}
	cases := []tc{
		// IPv4 listen/connect
		{name: "tcp4-listen-v4", spec: "TCP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork"},
		{name: "tcp4-listen-v6-wildcard", spec: "TCP4-LISTEN:0,bind=::,reuseaddr,fork", wantErr: "address family mismatch"},
		{name: "udp4-listen-v6-wildcard", spec: "UDP4-LISTEN:0,bind=::,reuseaddr,fork", wantErr: "address family mismatch"},
		{name: "tcp4-connect-v6-wildcard", spec: "TCP4:127.0.0.1:9,bind=::", wantErr: "address family"},
		{name: "udp4-connect-v6-wildcard", spec: "UDP4:127.0.0.1:9,bind=::", wantErr: "address family mismatch"},
		{name: "tls4-listen-v6-wildcard", spec: "OPENSSL-LISTEN:0,pf=ip4,bind=::,reuseaddr,fork,verify=0,cert=" + cert, wantErr: "address family mismatch"},
		{name: "ws4-listen-v6-wildcard", spec: "WS-LISTEN:0,pf=ip4,bind=::,reuseaddr,fork", wantErr: "address family mismatch"},
		{name: "quic4-listen-v6-wildcard", spec: "QUIC-LISTEN:0,pf=ip4,bind=::,reuseaddr,fork,verify=0,cert=" + cert, wantErr: "address family mismatch"},
		{name: "quic4-connect-v6-wildcard", spec: "QUIC:127.0.0.1:9,bind=::,verify=0", wantErr: "address family mismatch"},
		{name: "tls-connect-v6-wildcard", spec: "TLS:127.0.0.1:9,bind=::,verify=0", wantErr: "address family"},
		{name: "ws-connect-v6-wildcard", spec: "WS:127.0.0.1:9,bind=::", wantErr: "address family"},
		{name: "sctp4-listen-v6-wildcard", spec: "SCTP4-LISTEN:0,bind=::,reuseaddr,fork", wantErr: "address family mismatch", sctp: true},
		{name: "sctp4-connect-v6-wildcard", spec: "SCTP4:127.0.0.1:9,bind=::", wantErr: "address family", sctp: true},
		// IPv6
		{name: "tcp6-listen-v6", spec: "TCP6-LISTEN:0,bind=::1,reuseaddr,fork", ipv6: true},
		{name: "tcp6-listen-v4-wildcard", spec: "TCP6-LISTEN:0,bind=0.0.0.0,reuseaddr,fork", wantErr: "address family mismatch", ipv6: true},
		{name: "udp6-listen-v4-wildcard", spec: "UDP6-LISTEN:0,bind=0.0.0.0,reuseaddr,fork", wantErr: "address family mismatch", ipv6: true},
		{name: "tcp6-connect-v4-wildcard", spec: "TCP6:[::1]:9,bind=0.0.0.0", wantErr: "address family", ipv6: true},
		// Generic family: empty bind uses wildcard; explicit :: is kept.
		{name: "tcp-listen-generic-v4-bind", spec: "TCP-LISTEN:0,bind=127.0.0.1,reuseaddr,fork"},
		{name: "tcp-listen-generic-pf6", spec: "TCP-LISTEN:0,pf=ip6,bind=::1,reuseaddr,fork", ipv6: true},
		{name: "udp-listen-generic-v4", spec: "UDP-LISTEN:0,bind=127.0.0.1,reuseaddr,fork"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.sctp && !xio.FeatureSCTP {
				t.Skip("SCTP not enabled")
			}
			if tc.ipv6 {
				ln, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Skipf("no IPv6 loopback: %v", err)
				}
				_ = ln.Close()
			}
			o, err := openSpec(t, tc.spec)
			if tc.sctp && skipUnavailableSCTP(t, err) {
				return
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("open %s: %v", tc.spec, err)
				}
				t.Cleanup(func() { _ = o.Close() })
				return
			}
			if err == nil {
				_ = o.Close()
				t.Fatalf("open %s succeeded, want error containing %q", tc.spec, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error=%v want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestForkListenersAndDialersProvideWrapDial(t *testing.T) {
	cert, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	specs := []struct {
		name string
		spec string
		sctp bool
	}{
		{name: "tcp-listen", spec: "TCP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,readbytes=4"},
		{name: "udp-listen", spec: "UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,readbytes=4"},
		{name: "udp-recvfrom", spec: "UDP4-RECVFROM:0,bind=127.0.0.1,reuseaddr,fork,readbytes=4"},
		{name: "tls-listen", spec: "TLS-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,verify=0,cert=" + cert + ",readbytes=4"},
		{name: "ws-listen", spec: "WS-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,readbytes=4"},
		{name: "quic-listen", spec: "QUIC-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,verify=0,cert=" + cert + ",readbytes=4"},
		{name: "sctp-listen", spec: "SCTP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,readbytes=4", sctp: true},
		{name: "tcp-connect", spec: "TCP4:127.0.0.1:1,fork,readbytes=4"},
		{name: "tls-connect", spec: "TLS:127.0.0.1:1,fork,verify=0,readbytes=4"},
		{name: "ws-connect", spec: "WS:127.0.0.1:1,fork,readbytes=4"},
		{name: "sctp-connect", spec: "SCTP4:127.0.0.1:1,fork,readbytes=4", sctp: true},
	}
	for _, tc := range specs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.sctp && !xio.FeatureSCTP {
				t.Skip("SCTP not enabled")
			}
			o, err := openSpec(t, tc.spec)
			if tc.sctp && skipUnavailableSCTP(t, err) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			if o.WrapDial == nil {
				t.Fatal("WrapDial is nil")
			}
		})
	}
}

func streamLocalIP(t *testing.T, o *xio.Opened) net.IP {
	t.Helper()
	type localAddrer interface{ LocalAddr() net.Addr }
	la, ok := o.Stream.(localAddrer)
	if !ok {
		t.Fatalf("stream %T has no LocalAddr", o.Stream)
	}
	switch a := la.LocalAddr().(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	default:
		t.Fatalf("local addr %T %v", a, a)
		return nil
	}
}

func acceptOnce(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
}

func TestMatchingConnectBind(t *testing.T) {
	t.Run("tcp4", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		acceptOnce(t, ln)
		port := ln.Addr().(*net.TCPAddr).Port
		o, err := openSpec(t, fmt.Sprintf("TCP4:127.0.0.1:%d,bind=127.0.0.1,connect-timeout=2", port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		ip := streamLocalIP(t, o)
		if !ip.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("local IP %v, want 127.0.0.1", ip)
		}
	})
	t.Run("tcp4-host-port", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		acceptOnce(t, ln)
		port := ln.Addr().(*net.TCPAddr).Port
		o, err := openSpec(t, fmt.Sprintf("TCP4:127.0.0.1:%d,bind=127.0.0.1:0,connect-timeout=2", port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		ip := streamLocalIP(t, o)
		if !ip.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("local IP %v, want 127.0.0.1", ip)
		}
	})
	t.Run("udp4", func(t *testing.T) {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		port := pc.LocalAddr().(*net.UDPAddr).Port
		o, err := openSpec(t, fmt.Sprintf("UDP4:127.0.0.1:%d,bind=127.0.0.1", port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		ip := streamLocalIP(t, o)
		if !ip.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("local IP %v, want 127.0.0.1", ip)
		}
	})
}

func TestListenWithoutBindOpensWildcard(t *testing.T) {
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "")
	for _, spec := range []string{
		"TCP-LISTEN:0,reuseaddr,fork",
		"TCP4-LISTEN:0,reuseaddr,fork",
		"UDP-LISTEN:0,reuseaddr,fork",
		"UDP4-LISTEN:0,reuseaddr,fork",
	} {
		t.Run(spec, func(t *testing.T) {
			o, err := openSpec(t, spec)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			if o.Listener == nil {
				t.Fatal("expected Listener")
			}
			host, port, err := net.SplitHostPort(o.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsUnspecified() || ip.To4() == nil {
				t.Fatalf("default listen addr %s, want IPv4 wildcard", o.Listener.Addr())
			}
			if !strings.HasPrefix(spec, "TCP") {
				return
			}
			c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
			if err != nil {
				t.Fatalf("dial wildcard listener: %v", err)
			}
			_ = c.Close()
		})
	}
}

func TestHostnameBind(t *testing.T) {
	t.Run("listen", func(t *testing.T) {
		o, err := openSpec(t, "TCP4-LISTEN:0,bind=localhost,reuseaddr,fork")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		host, port, err := net.SplitHostPort(o.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() || ip.To4() == nil {
			t.Fatalf("bind=localhost listen addr %s, want IPv4 loopback", o.Listener.Addr())
		}
		c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			t.Fatalf("dial localhost listener: %v", err)
		}
		_ = c.Close()
	})
	t.Run("connect", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		acceptOnce(t, ln)
		port := ln.Addr().(*net.TCPAddr).Port
		o, err := openSpec(t, fmt.Sprintf("TCP4:127.0.0.1:%d,bind=localhost,connect-timeout=2", port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		ip := streamLocalIP(t, o)
		if ip == nil || !ip.IsLoopback() || ip.To4() == nil {
			t.Fatalf("bind=localhost local IP %v, want IPv4 loopback", ip)
		}
	})
}
