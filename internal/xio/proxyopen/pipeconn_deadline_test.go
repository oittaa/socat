package proxyopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

type closeCounter struct {
	io.ReadCloser
	w      io.WriteCloser
	closes atomic.Int32
}

func (c *closeCounter) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *closeCounter) Close() error {
	c.closes.Add(1)
	if c.ReadCloser != nil {
		return c.ReadCloser.Close()
	}
	return c.w.Close()
}

func deadlineWatch(t *testing.T, fn func() (int, error)) (int, error) {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := fn()
		done <- result{n, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	select {
	case got := <-done:
		return got.n, got.err
	case <-ctx.Done():
		t.Fatal("I/O ignored deadline")
		return 0, ctx.Err()
	}
}

func TestPipeConnReadDeadlineUnblocks(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close(); _ = pr.Close() })
	c := newPipeConn(pr, pw, staticAddr("h2", "l"), staticAddr("h2", "r"), nil)
	if err := c.SetReadDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err := deadlineWatch(t, func() (int, error) { return c.Read(make([]byte, 1)) })
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("n=%d err=%v want deadline exceeded", n, err)
	}
}

func TestPipeConnWriteDeadlineUnblocks(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close(); _ = pr.Close() })
	c := newPipeConn(pr, pw, staticAddr("h2", "l"), staticAddr("h2", "r"), nil)
	if err := c.SetWriteDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err := deadlineWatch(t, func() (int, error) { return c.Write([]byte("x")) })
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("n=%d err=%v want deadline exceeded", n, err)
	}
}

func TestPipeConnDeadlineDoesNotCloseStream(t *testing.T) {
	readR, readW := io.Pipe()
	writeR, writeW := io.Pipe()
	r := &closeCounter{ReadCloser: readR}
	w := &closeCounter{w: writeW}
	c := newPipeConn(r, w, staticAddr("h2", "l"), staticAddr("h2", "r"), nil)
	t.Cleanup(func() { _ = c.Close(); _ = readW.Close(); _ = writeR.Close() })

	if err := c.SetDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := deadlineWatch(t, func() (int, error) { return c.Read(make([]byte, 1)) }); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read err=%v", err)
	}
	if _, err := deadlineWatch(t, func() (int, error) { return c.Write([]byte("x")) }); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write err=%v", err)
	}
	if r.closes.Load() != 0 || w.closes.Load() != 0 {
		t.Fatalf("deadline closed sides read=%d write=%d", r.closes.Load(), w.closes.Load())
	}

	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := readW.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2)
	n, err := c.Read(got)
	if err != nil || string(got[:n]) != "ok" {
		t.Fatalf("Read after deadline n=%d err=%v got=%q", n, err, got[:n])
	}
	wrote := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(writeR, make([]byte, 1))
		wrote <- err
	}()
	if _, err := c.Write([]byte("z")); err != nil {
		t.Fatal(err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	if r.closes.Load() != 0 || w.closes.Load() != 0 {
		t.Fatalf("post-deadline I/O closed sides read=%d write=%d", r.closes.Load(), w.closes.Load())
	}
}

func TestPipeConnSetDeadlineWakesBlockedRead(t *testing.T) {
	pr, pw := io.Pipe()
	r := &closeCounter{ReadCloser: pr}
	c := newPipeConn(r, pw, staticAddr("h2", "l"), staticAddr("h2", "r"), nil)
	t.Cleanup(func() { _ = c.Close(); _ = pw.Close() })
	entered := make(chan struct{})
	var once sync.Once
	pipeConnWaitHook = func() { once.Do(func() { close(entered) }) }
	t.Cleanup(func() { pipeConnWaitHook = nil })
	n, err := waitThenDeadline(t, entered, func() (int, error) { return c.Read(make([]byte, 1)) }, c.SetReadDeadline)
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if r.closes.Load() != 0 {
		t.Fatalf("woke Read by closing the stream (%d)", r.closes.Load())
	}
}

func TestPipeConnSetDeadlineWakesBlockedWrite(t *testing.T) {
	pr, pw := io.Pipe()
	w := &closeCounter{w: pw}
	c := newPipeConn(pr, w, staticAddr("h2", "l"), staticAddr("h2", "r"), nil)
	t.Cleanup(func() { _ = c.Close(); _ = pr.Close() })
	entered := make(chan struct{})
	var once sync.Once
	pipeConnWaitHook = func() { once.Do(func() { close(entered) }) }
	t.Cleanup(func() { pipeConnWaitHook = nil })
	n, err := waitThenDeadline(t, entered, func() (int, error) { return c.Write([]byte("x")) }, c.SetWriteDeadline)
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("n=%d err=%v want n=0, deadline exceeded", n, err)
	}
	if w.closes.Load() != 0 {
		t.Fatalf("woke Write by closing the stream (%d)", w.closes.Load())
	}
}

func waitThenDeadline(t *testing.T, entered <-chan struct{}, op func() (int, error), set func(time.Time) error) (int, error) {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := op()
		done <- result{n, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("I/O did not block before deadline")
	}
	if err := set(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		return got.n, got.err
	case <-ctx.Done():
		t.Fatal("blocked I/O ignored SetDeadline")
		return 0, ctx.Err()
	}
}

func TestH2cCONNECTrcvtimeoThenEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	var p http.Protocols
	p.SetHTTP1(false)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: connectEchoHandler(), Protocols: &p}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	s, err := parse.ParseSpec(fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,h2c,proxyport=%s,rcvtimeo=0.15", port))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	o, err := openProxyConnect(ctx, mustAddr(t, s), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	n, err := o.Stream.Read(make([]byte, 1))
	if n != 0 || !xio.IsTimeoutErr(err) {
		t.Fatalf("rcvtimeo Read n=%d err=%v", n, err)
	}
	payload := []byte("after-timeout")
	if _, err := o.Stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(o.Stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q", got)
	}
}
