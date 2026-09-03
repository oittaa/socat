package wsopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

type wsPairResult struct {
	conn net.Conn
	err  error
}

func newWSTestPair(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

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
		t.Fatal(err)
	}
	client, err := dialWS(
		context.Background(),
		"tcp4",
		"127.0.0.1",
		fmt.Sprint(addr.Port),
		fmt.Sprintf("ws://127.0.0.1:%d/", addr.Port),
		spec,
		&xio.Global{Log: logx.New()},
		nil,
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	result := <-serverResult
	if result.err != nil {
		_ = client.Close()
		t.Fatal(result.err)
	}
	t.Cleanup(func() {
		closeWSTestConn(client)
		closeWSTestConn(result.conn)
	})
	return client, result.conn
}

func closeWSTestConn(conn net.Conn) {
	_ = conn.Close()
}

func TestWSNetConnReadDeadline(t *testing.T) {
	_, server := newWSTestPair(t)
	if err := server.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err := server.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("Read succeeded without data")
	}
	var timeout interface{ Timeout() bool }
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("Read error %v is not a timeout", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("read deadline took %s", elapsed)
	}
	if err := server.SetDeadline(time.Time{}); err == nil {
		t.Fatal("read timeout left the connection open")
	}
	started = time.Now()
	_ = server.Close()
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Close after deadline took %s", elapsed)
	}
}

func TestWSNetConnWriteDeadline(t *testing.T) {
	client, _ := newWSTestPair(t)
	payload := make([]byte, 8<<20)
	if err := client.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err := client.Write(payload)
	if err == nil {
		t.Fatal("Write succeeded while the peer was not reading")
	}
	var timeout interface{ Timeout() bool }
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("Write error %v is not a timeout", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("write deadline took %s", elapsed)
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
