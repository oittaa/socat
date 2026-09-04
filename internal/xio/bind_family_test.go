package xio_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
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

func TestTLSAndWSSListenValidationOrder(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	missingCert := filepath.ToSlash(filepath.Join(t.TempDir(), "missing.pem"))
	for _, typ := range []string{"TLS-LISTEN", "WSS-LISTEN"} {
		t.Run(typ, func(t *testing.T) {
			o, err := openSpec(t, typ+":"+port+",pf=ip4,bind=127.0.0.1,verify=0,cert="+missingCert)
			if err == nil {
				_ = o.Close()
				t.Fatal("occupied port and missing certificate must fail")
			}
			if typ == "TLS-LISTEN" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("certificate must be checked before binding: %v", err)
				}
			} else {
				var op *net.OpError
				if !errors.As(err, &op) || op.Op != "listen" {
					t.Fatalf("binding must precede certificate loading: %v", err)
				}
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
