package xio

import (
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func TestIPInRangeHostnameMask(t *testing.T) {
	// Classic FDLEAK: range=localhost:255.255.255.255
	ok, err := ipInRange(net.ParseIP("127.0.0.1"), "localhost:255.255.255.255")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("127.0.0.1 should match range=localhost:255.255.255.255")
	}
	ok, err = ipInRange(net.ParseIP("127.1.0.1"), "localhost:255.255.255.255")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("127.1.0.1 should not match range=localhost:255.255.255.255")
	}
}

func TestPeerFilterNoOptionsDoesNotAllocate(t *testing.T) {
	filter := NewPeerFilter(parse.Spec{}, nil)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	if got := testing.AllocsPerRun(1000, func() {
		if err := filter.AllowAddr(peer, nil); err != nil {
			t.Fatal(err)
		}
	}); got != 0 {
		t.Fatalf("AllowAddr allocations = %v, want 0", got)
	}
}

func TestCompiledIPRangeForms(t *testing.T) {
	tests := []struct {
		name string
		peer string
		spec string
		want bool
	}{
		{"cidr-match", "127.1.2.3", "127.0.0.0/8", true},
		{"cidr-miss", "192.0.2.1", "127.0.0.0/8", false},
		{"ipv6-cidr", "2001:db8::9", "[2001:db8::]/32", true},
		{"address-mask", "127.9.8.7", "127.0.0.0:255.0.0.0", true},
		{"exact", "192.0.2.1", "192.0.2.1", true},
		{"hex-sockaddr", "127.8.9.10", "x0000x7f000000:x0000xff000000", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := compileIPRange(tc.spec, net.DefaultResolver)
			if err != nil {
				t.Fatal(err)
			}
			if got := matcher(net.ParseIP(tc.peer)); got != tc.want {
				t.Fatalf("match(%s, %q) = %v, want %v", tc.peer, tc.spec, got, tc.want)
			}
		})
	}
}

// nestNetConn is a TLS-like wrapper: NetConn() returns the next layer.
type nestNetConn struct {
	net.Conn
}

func (c nestNetConn) NetConn() net.Conn { return c.Conn }

func TestCloseRefusedPeerNil(t *testing.T) {
	CloseRefusedPeer(nil)
}

func TestCloseRefusedPeerDrainsNestedTCPWrappers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	payload := []byte("already-wrote")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}

	accepted, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	timeoutConn, err := NewSocketTimeoutConn(parse.Spec{}, accepted)
	if err != nil {
		t.Fatal(err)
	}
	// TLS-LISTEN Accept yields tls.Conn → SocketTimeoutConn → TCPConn.
	refused := nestNetConn{Conn: nestNetConn{Conn: timeoutConn}}
	if unwrapNetConn(refused) != accepted {
		t.Fatalf("unwrapNetConn stopped at %T, want %T", unwrapNetConn(refused), accepted)
	}

	CloseRefusedPeer(refused)

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	_, err = client.Read(buf)
	if isConnReset(err) {
		t.Fatalf("client that already wrote saw a reset: %v", err)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("client read after refusal: %v", err)
	}
}

func isConnReset(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection reset")
}
