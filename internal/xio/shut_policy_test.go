package xio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

type recordingStream struct {
	writes    [][]byte
	shutdowns int
	closes    int
	readFrom  *bytes.Reader
	writeTo   bytes.Buffer
}

func (s *recordingStream) Read(p []byte) (int, error) {
	if s.readFrom == nil {
		return 0, io.EOF
	}
	return s.readFrom.Read(p)
}

func (s *recordingStream) Write(p []byte) (int, error) {
	s.writes = append(s.writes, append([]byte(nil), p...))
	return s.writeTo.Write(p)
}

func (s *recordingStream) Close() error {
	s.closes++
	return nil
}

func (s *recordingStream) ShutdownWrite() error {
	s.shutdowns++
	return nil
}

func wrapSpec(t *testing.T, spec string, inner relay.Stream) relay.Stream {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := WrapCommon(s, inner)
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func TestSelectedShutPolicyOrderAndZero(t *testing.T) {
	tests := []struct {
		spec string
		want shutPolicy
	}{
		{spec: "TCP:127.0.0.1:9", want: shutUnspecified},
		{spec: "TCP:127.0.0.1:9,shut-none", want: shutNone},
		{spec: "TCP:127.0.0.1:9,shut-down", want: shutDown},
		{spec: "TCP:127.0.0.1:9,shut-close", want: shutClose},
		{spec: "TCP:127.0.0.1:9,shut-null", want: shutNull},
		{spec: "TCP:127.0.0.1:9,shut=none", want: shutNone},
		{spec: "TCP:127.0.0.1:9,shut=down", want: shutDown},
		{spec: "TCP:127.0.0.1:9,shut=close", want: shutClose},
		{spec: "TCP:127.0.0.1:9,shut=null", want: shutNull},
		{spec: "TCP:127.0.0.1:9,shut-none,shut-close", want: shutClose},
		{spec: "TCP:127.0.0.1:9,shut-close,shut-none", want: shutNone},
		{spec: "TCP:127.0.0.1:9,shut-null,shut-down", want: shutDown},
		{spec: "TCP:127.0.0.1:9,shut-down,shut-null", want: shutNull},
		{spec: "TCP:127.0.0.1:9,shut=close,shut-none", want: shutNone},
		{spec: "TCP:127.0.0.1:9,shut-none,shut=close", want: shutClose},
		{spec: "TCP:127.0.0.1:9,shut-none,shut-close=0", want: shutNone},
		{spec: "TCP:127.0.0.1:9,shut-close,shut-none=0", want: shutClose},
		{spec: "TCP:127.0.0.1:9,shut-down=0,shut-null", want: shutNull},
		{spec: "TCP:127.0.0.1:9,shut=0,shut-down", want: shutDown},
		{spec: "TCP:127.0.0.1:9,shut-null,shut=0", want: shutNull},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			s, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			got, err := selectedShutPolicy(s)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("policy=%d want %d", got, tc.want)
			}
		})
	}
}

func TestSelectedShutPolicyInvalidValue(t *testing.T) {
	s, err := parse.ParseSpec("TCP:127.0.0.1:9,shut=foo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectedShutPolicy(s); err == nil {
		t.Fatal("expected error for shut=foo")
	}
	if _, err := WrapCommon(s, &recordingStream{}); err == nil {
		t.Fatal("WrapCommon should reject shut=foo")
	}
	for _, spec := range []string{
		"TCP:127.0.0.1:9,shut-none=garbage",
		"TCP:127.0.0.1:9,shut-down=false",
		"TCP:127.0.0.1:9,shut-close=no",
		"TCP:127.0.0.1:9,shut-null=off",
	} {
		parsed, err := parse.ParseSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := selectedShutPolicy(parsed); err == nil {
			t.Fatalf("expected error for %s", spec)
		}
		if _, err := WrapCommon(parsed, &recordingStream{}); err == nil {
			t.Fatalf("WrapCommon should reject %s", spec)
		}
	}
}

func TestShutPolicyStreamActions(t *testing.T) {
	tests := []struct {
		spec      string
		shutdowns int
		closes    int
		nilWrite  bool
		wantErr   bool
	}{
		{spec: "TCP:127.0.0.1:9,shut-none", shutdowns: 0, closes: 0},
		{spec: "TCP:127.0.0.1:9,shut-down", wantErr: true},
		{spec: "TCP:127.0.0.1:9,shut-close", shutdowns: 0, closes: 1},
		{spec: "TCP:127.0.0.1:9,shut-null", shutdowns: 0, closes: 0, nilWrite: true},
		{spec: "TCP:127.0.0.1:9,shut=none", shutdowns: 0, closes: 0},
		{spec: "TCP:127.0.0.1:9,shut=down", wantErr: true},
		{spec: "TCP:127.0.0.1:9,shut=close", shutdowns: 0, closes: 1},
		{spec: "TCP:127.0.0.1:9,shut=null", shutdowns: 0, closes: 0, nilWrite: true},
		{spec: "TCP:127.0.0.1:9,shut-null,shut-close", shutdowns: 0, closes: 1},
		{spec: "TCP:127.0.0.1:9,shut-close,shut-null", shutdowns: 0, closes: 0, nilWrite: true},
		{spec: "TCP:127.0.0.1:9,shut-close,shut-none", shutdowns: 0, closes: 0},
		{spec: "TCP:127.0.0.1:9,shut-none,shut-close=0", shutdowns: 0, closes: 0},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			inner := &recordingStream{}
			stream := wrapSpec(t, tc.spec, inner)
			err := stream.ShutdownWrite()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected shut-down error on a non-socket")
				}
				if inner.shutdowns != 0 || inner.closes != 0 {
					t.Fatalf("fallback ShutdownWrite/Close on non-socket: shutdowns=%d closes=%d", inner.shutdowns, inner.closes)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if inner.shutdowns != tc.shutdowns || inner.closes != tc.closes {
				t.Fatalf("shutdowns=%d closes=%d want shutdowns=%d closes=%d",
					inner.shutdowns, inner.closes, tc.shutdowns, tc.closes)
			}
			gotNil := false
			for _, w := range inner.writes {
				if len(w) == 0 {
					gotNil = true
				}
			}
			if gotNil != tc.nilWrite {
				t.Fatalf("nil write=%v want %v", gotNil, tc.nilWrite)
			}
		})
	}
}

func TestShutNoneDoesNotCloseOnShutdownWrite(t *testing.T) {
	inner := &recordingStream{}
	stream := wrapSpec(t, "TCP:127.0.0.1:9,shut-none", inner)
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if inner.shutdowns != 0 {
		t.Fatalf("ShutdownWrite should be a no-op, got %d", inner.shutdowns)
	}
	if inner.closes != 1 {
		t.Fatalf("Close calls=%d want 1", inner.closes)
	}
}

func TestShutPolicyPreservesDeadlineUnwrap(t *testing.T) {
	for _, opt := range []string{"shut-none", "shut-down", "shut-close", "shut-null", "shut=down"} {
		t.Run(opt, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			spec := parse.Spec{Options: []parse.Option{
				{Name: "rcvtimeo", Value: "0.02", Has: true},
				{Name: "sndtimeo", Value: "0.02", Has: true},
			}}
			parsed, err := parse.ParseSpec("TCP:127.0.0.1:9," + opt)
			if err != nil {
				t.Fatal(err)
			}
			spec.Options = append(spec.Options, parsed.Options...)
			stream, err := WrapCommon(spec, timeoutPipeStream(client))
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			if found, err := relay.SetStreamReadDeadline(stream, deadline); err != nil || !found {
				t.Fatalf("SetStreamReadDeadline found=%v err=%v", found, err)
			}
			if found, err := relay.SetStreamWriteDeadline(stream, deadline); err != nil || !found {
				t.Fatalf("SetStreamWriteDeadline found=%v err=%v", found, err)
			}
		})
	}
}

func TestShutNoneSelectedForExec(t *testing.T) {
	none, err := parse.ParseSpec("EXEC:true,shut-none")
	if err != nil {
		t.Fatal(err)
	}
	if !ShutNoneSelected(none) {
		t.Fatal("shut-none should select EXEC wait-without-kill")
	}
	over, err := parse.ParseSpec("EXEC:true,shut-none,shut-close")
	if err != nil {
		t.Fatal(err)
	}
	if ShutNoneSelected(over) {
		t.Fatal("later shut-close should win over shut-none")
	}
	rev, err := parse.ParseSpec("EXEC:true,shut-close,shut=none")
	if err != nil {
		t.Fatal(err)
	}
	if !ShutNoneSelected(rev) {
		t.Fatal("later shut=none should win")
	}
	off, err := parse.ParseSpec("EXEC:true,shut-none=0")
	if err != nil {
		t.Fatal(err)
	}
	if ShutNoneSelected(off) {
		t.Fatal("shut-none=0 must not select")
	}
}

type failWriteStream struct{ recordingStream }

func (s *failWriteStream) Write(p []byte) (int, error) {
	s.writes = append(s.writes, append([]byte(nil), p...))
	return 0, io.ErrClosedPipe
}

func TestShutNullIgnoresWriteError(t *testing.T) {
	inner := &failWriteStream{}
	stream := wrapSpec(t, "TCP:127.0.0.1:9,shut-null", inner)
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatalf("classic shut-null ignores xiowrite error: %v", err)
	}
	if inner.shutdowns != 0 {
		t.Fatalf("shut-null must not also ShutdownWrite: shutdowns=%d", inner.shutdowns)
	}
	if len(inner.writes) != 1 || len(inner.writes[0]) != 0 {
		t.Fatalf("writes=%v want one empty datagram", inner.writes)
	}
}

func TestIsNotSockMatchesNotSocketError(t *testing.T) {
	if !isNotSock(notSocketError()) {
		t.Fatal("notSocketError must satisfy isNotSock")
	}
	if !isNotSock(fmt.Errorf("shut-down: %w", notSocketError())) {
		t.Fatal("wrapped notSocketError must satisfy isNotSock")
	}
}

func TestShutDownOnPipeReportsNotSocket(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	stream := wrapSpec(t, "PIPE,shut-down", FileStream(w))
	err = stream.ShutdownWrite()
	if err == nil || !isNotSock(err) {
		t.Fatalf("err=%v want not-a-socket", err)
	}
	if _, err := w.Write([]byte("still-open")); err != nil {
		t.Fatalf("pipe must stay open after shut-down: %v", err)
	}
}

// tlsLikeConn is a crypto/tls.Conn stand-in: CloseWrite is TLS close-notify,
// NetConn exposes the raw socket, and SyscallConn is not implemented.
type tlsLikeConn struct {
	conn        net.Conn
	closeWrites int
}

func (c *tlsLikeConn) Read(p []byte) (int, error)         { return c.conn.Read(p) }
func (c *tlsLikeConn) Write(p []byte) (int, error)        { return c.conn.Write(p) }
func (c *tlsLikeConn) Close() error                       { return c.conn.Close() }
func (c *tlsLikeConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *tlsLikeConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *tlsLikeConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *tlsLikeConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *tlsLikeConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *tlsLikeConn) CloseWrite() error                  { c.closeWrites++; return nil }
func (c *tlsLikeConn) NetConn() net.Conn                  { return c.conn }

func TestShutDownUsesRawSocketNotCloseWrite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	peerCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			peerCh <- nil
			return
		}
		peerCh <- c
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()
	peer := <-peerCh
	if peer == nil {
		t.Fatal("accept failed")
	}
	defer func() { _ = peer.Close() }()
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))

	tlsLike := &tlsLikeConn{conn: cli}
	stream := wrapSpec(t, "TCP:127.0.0.1:9,shut-down", relay.NetStream{Conn: tlsLike})
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	if tlsLike.closeWrites != 0 {
		t.Fatalf("CloseWrite calls=%d want 0 (raw shutdown, not TLS close-notify)", tlsLike.closeWrites)
	}
	buf := make([]byte, 8)
	n, err := peer.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("peer Read n=%d err=%v want EOF from shutdown", n, err)
	}
}

type udpTestStream struct{ *net.UDPConn }

func (u udpTestStream) ShutdownWrite() error { return nil }

func TestShutPolicyDatagramEndpoints(t *testing.T) {
	tests := []struct {
		opt   string
		check func(t *testing.T, local, peer *net.UDPConn, wrapped relay.Stream)
	}{
		{
			opt: "shut-none",
			check: func(t *testing.T, local, peer *net.UDPConn, wrapped relay.Stream) {
				if err := wrapped.ShutdownWrite(); err != nil {
					t.Fatal(err)
				}
				if _, err := wrapped.Write([]byte("still-open")); err != nil {
					t.Fatalf("write after shut-none: %v", err)
				}
			},
		},
		{
			opt: "shut-down",
			check: func(t *testing.T, local, peer *net.UDPConn, wrapped relay.Stream) {
				if err := wrapped.ShutdownWrite(); err != nil {
					t.Fatal(err)
				}
				if _, err := wrapped.Write([]byte("after-down")); err == nil {
					t.Fatal("write after shut-down succeeded")
				}
			},
		},
		{
			opt: "shut-close",
			check: func(t *testing.T, local, peer *net.UDPConn, wrapped relay.Stream) {
				if err := wrapped.ShutdownWrite(); err != nil {
					t.Fatal(err)
				}
				if _, err := local.Write([]byte("after-close")); err == nil {
					t.Fatal("Write after shut-close succeeded")
				}
			},
		},
		{
			opt: "shut-null",
			check: func(t *testing.T, local, peer *net.UDPConn, wrapped relay.Stream) {
				_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
				done := make(chan []byte, 1)
				go func() {
					buf := make([]byte, 16)
					n, _, err := peer.ReadFromUDP(buf)
					if err != nil {
						done <- []byte("err:" + err.Error())
						return
					}
					done <- buf[:n]
				}()
				if err := wrapped.ShutdownWrite(); err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-done:
					if string(got) != "" {
						t.Fatalf("peer got %q want empty datagram", got)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("timed out waiting for shut-null datagram")
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.opt, func(t *testing.T) {
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			local, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, peer.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = local.Close() }()
			spec, err := parse.ParseSpec("UDP-DATAGRAM:127.0.0.1:9," + tc.opt)
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := WrapCommon(spec, udpTestStream{UDPConn: local})
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, local, peer, wrapped)
		})
	}
}
