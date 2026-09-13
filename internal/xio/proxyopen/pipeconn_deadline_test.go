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
	"testing"
	"testing/synctest"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestPipeConnDeadlineWakesReadAndAllowsReuse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		readR, readW := io.Pipe()
		writeR, writeW := newReqPipe(8)
		c := newPipeConn(readR, writeW, nil, nil, nil)
		defer func() { _ = c.Close() }()
		defer func() { _ = readW.Close() }()
		defer func() { _ = writeR.Close() }()
		done := make(chan writeResult, 1)
		go func() { n, err := c.Read(make([]byte, 1)); done <- writeResult{n, err} }()
		synctest.Wait()
		_ = c.SetDeadline(time.Now())
		if got := <-done; got.n != 0 || !errors.Is(got.err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read=%+v", got)
		}
		if n, err := c.Write([]byte("x")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write=%d, %v", n, err)
		}
		_ = c.SetDeadline(time.Time{})
		if _, err := readW.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ok" {
			t.Fatalf("Read=%q, %v", buf, err)
		}
		if _, err := c.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(writeR, buf); err != nil || string(buf) != "ok" {
			t.Fatalf("peer=%q, %v", buf, err)
		}
	})
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

	n, err := o.Stream().Read(make([]byte, 1))
	if n != 0 || !xio.IsTimeoutErr(err) {
		t.Fatalf("rcvtimeo Read n=%d err=%v", n, err)
	}
	payload := []byte("after-timeout")
	if _, err := o.Stream().Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(o.Stream(), got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q", got)
	}
}
