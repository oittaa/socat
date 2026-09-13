//go:build linux || darwin

package proxyopen

import (
	"io"
	"net"
	"strconv"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestPROXYHTTP1BufferedResponseAppliesDescriptorOptions(t *testing.T) {
	const payload = "coalesced-app-data"
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{name: "headers-only", payload: ""},
		{name: "headers-and-payload", payload: payload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, peer := proxyHTTP1TCPHandshake(t, tc.payload)
			_, isSyscall := conn.(syscall.Conn)
			_, hasNetConn := conn.(interface{ NetConn() net.Conn })
			if tc.payload == "" {
				if !isSyscall {
					t.Fatal("unbuffered CONNECT must expose the TCP descriptor")
				}
			} else {
				if isSyscall {
					t.Fatal("buffered CONNECT must not implement syscall.Conn; relay poll or splice would skip the prefix")
				}
				if !hasNetConn {
					t.Fatal("buffered CONNECT must expose NetConn for option lifecycle")
				}
			}

			st, err := xio.SetupConnectedStream(mustPROXYOpts(t, "cloexec=0,sndbuf-late=65536"), relay.NetStream{Conn: conn})
			if err != nil {
				t.Fatalf("SetupConnectedStream: %v", err)
			}
			t.Cleanup(func() { _ = st.Close() })

			tcp := underlyingTCP(t, st)
			if tcpSockopt(t, tcp, unix.SO_SNDBUF) < 65536 {
				t.Fatal("sndbuf-late did not reach the TCP socket")
			}
			if connFDFlags(t, tcp)&unix.FD_CLOEXEC != 0 {
				t.Fatal("cloexec=0 left FD_CLOEXEC set")
			}

			props := st.StreamProps()
			if tc.payload != "" && (props.ZeroCopyRead != nil || props.ZeroCopyWrite != nil) {
				t.Fatal("zero-copy would skip buffered CONNECT payload")
			}

			if tc.payload != "" {
				got := make([]byte, 1)
				if n, err := st.Read(got); err != nil || n != 1 || got[0] != payload[0] {
					t.Fatalf("short prefix read n=%d err=%v data=%q", n, err, got[:n])
				}
				rest := make([]byte, len(payload)-1)
				if _, err := io.ReadFull(st, rest); err != nil || string(rest) != payload[1:] {
					t.Fatalf("remaining prefix=%q err=%v", rest, err)
				}
			}

			if err := st.ShutdownWrite(); err != nil {
				t.Fatalf("ShutdownWrite: %v", err)
			}
			n, err := peer.Read(make([]byte, 1))
			if n != 0 || err != io.EOF {
				t.Fatalf("peer Read after half-close n=%d err=%v want EOF", n, err)
			}
		})
	}
}

func TestPROXYHTTP1CoalescedCONNECTOpenerAppliesCloexec(t *testing.T) {
	const payload = "head-bytes"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		if !drainHTTP1CONNECTRequest(t, c) {
			return
		}
		if _, err := io.WriteString(c, http1ConnectEstablished+payload); err != nil {
			return
		}
		_, _ = io.Copy(c, c)
	}()

	spec := "PROXY:127.0.0.1:127.0.0.1:9,proxyport=" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port) + ",cloexec=0,sndbuf-late=65536"
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openProxyConnect(t.Context(), mustAddr(t, s), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(o.Stream(), got); err != nil || string(got) != payload {
		t.Fatalf("prefix=%q err=%v", got, err)
	}
	echo := []byte("tail-bytes")
	if _, err := o.Stream().Write(echo); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(echo))
	if _, err := io.ReadFull(o.Stream(), got); err != nil || string(got) != string(echo) {
		t.Fatalf("echo=%q err=%v", got, err)
	}

	tcp := underlyingTCP(t, o.Stream())
	if tcpSockopt(t, tcp, unix.SO_SNDBUF) < 65536 {
		t.Fatal("sndbuf-late did not reach the TCP socket")
	}
	if connFDFlags(t, tcp)&unix.FD_CLOEXEC != 0 {
		t.Fatal("cloexec=0 left FD_CLOEXEC set")
	}
}

func mustPROXYOpts(t *testing.T, opts string) addrconfig.Address {
	t.Helper()
	s, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9," + opts)
	if err != nil {
		t.Fatal(err)
	}
	return mustAddr(t, s)
}

func underlyingTCP(t *testing.T, v any) *net.TCPConn {
	t.Helper()
	for hops := 0; v != nil && hops < 8; hops++ {
		switch c := v.(type) {
		case *net.TCPConn:
			return c
		case relay.NetStream:
			v = c.Conn
		case interface{ UnwrapStream() relay.Stream }:
			next := c.UnwrapStream()
			if next == nil || next == v {
				t.Fatalf("stopped unwrapping at %T", v)
			}
			v = next
		case interface{ NetConn() net.Conn }:
			next := c.NetConn()
			if next == nil || next == v {
				t.Fatalf("stopped unwrapping at %T", v)
			}
			v = next
		default:
			t.Fatalf("underlying %T, want *net.TCPConn", v)
		}
	}
	t.Fatalf("underlying %T, want *net.TCPConn", v)
	return nil
}

func tcpSockopt(t *testing.T, tc *net.TCPConn, opt int) int {
	t.Helper()
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

func connFDFlags(t *testing.T, tc *net.TCPConn) int {
	t.Helper()
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var ferr error
	if err := raw.Control(func(fd uintptr) {
		flags, ferr = unix.FcntlInt(fd, unix.F_GETFD, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if ferr != nil {
		t.Fatal(ferr)
	}
	return flags
}
