package wsopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

type wsPairResult struct {
	conn net.Conn
	err  error
}

func newWSTestPair(tb testing.TB) (net.Conn, net.Conn) {
	tb.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = ln.Close() })

	serverResult := make(chan wsPairResult, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverResult <- wsPairResult{err: err}
			return
		}
		conn, err := upgradeConn(raw, "/", "", "", time.Second)
		if err != nil {
			_ = raw.Close()
		}
		serverResult <- wsPairResult{conn: conn, err: err}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	spec, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d", addr.Port))
	if err != nil {
		tb.Fatal(err)
	}
	client, err := dialWS(
		context.Background(),
		wsDialTarget{
			Network: "tcp4",
			Scheme:  "ws",
			Host:    addrconfig.HostFromText("127.0.0.1"),
			Port:    addrconfig.PortFromText(fmt.Sprint(addr.Port)),
			Path:    "/",
		},
		mustAddr(tb, spec),
		&xio.Global{Log: logx.New()},
		nil,
		time.Second,
	)
	if err != nil {
		tb.Fatal(err)
	}
	result := <-serverResult
	if result.err != nil {
		_ = client.Close()
		tb.Fatal(result.err)
	}
	tb.Cleanup(func() {
		closeWSTestConn(client)
		closeWSTestConn(result.conn)
	})
	return client, result.conn
}

func closeWSTestConn(conn net.Conn) {
	_ = conn.Close()
}

func TestWSReadDeadlineDoesNotCloseConn(t *testing.T) {
	client, server := newWSTestPair(t)
	if err := client.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	readErr := make(chan error, 1)
	go func() {
		_, err := client.Read(buf)
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("read deadline did not fire")
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "next" {
		t.Fatalf("after deadline: %q %v", buf, err)
	}
}

func TestWSNetConnCloseFrameBecomesEOF(t *testing.T) {
	client, server := newWSTestPair(t)
	done := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 1))
		done <- err
	}()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Read error = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer close did not unblock Read")
	}
}

func BenchmarkWSNetConnWrite(b *testing.B) {
	client, server := newWSTestPair(b)
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, server)
		close(done)
	}()
	payload := make([]byte, 8192)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		if _, err := client.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	_ = client.Close()
	<-done
}
