//go:build linux

package posixmqopen

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/fileopen"
	"golang.org/x/sys/unix"
)

var mqSeq atomic.Uint64

func skipIfNoMQ(t *testing.T) {
	t.Helper()
	name := fmt.Sprintf("/socat-mqprobe-%d-%d", os.Getpid(), mqSeq.Add(1))
	fd, err := mqOpen(name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0o600, nil)
	if err != nil {
		t.Skipf("no POSIX MQ: %v", err)
	}
	_ = mqClose(fd)
	_ = mqUnlink(name)
}

func testQueue(t *testing.T) string {
	t.Helper()
	skipIfNoMQ(t)
	name := fmt.Sprintf("/socat-t-%d-%d", os.Getpid(), mqSeq.Add(1))
	t.Cleanup(func() { _ = mqUnlink(name) })
	return name
}

func testGlobal() *xio.Global {
	return &xio.Global{Log: logx.New(), BlockSize: 8192}
}

func sendMsg(t *testing.T, q, msg string, prio uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel(fmt.Sprintf("POSIXMQ-SEND:%s,mq-prio=%d", q, prio))
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(ctx, ch, xio.ModeWrite, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if _, err := io.WriteString(o.EffectiveStream(), msg); err != nil {
		t.Fatal(err)
	}
}

func TestPOSIXMQKeywordRDWR(t *testing.T) {
	skipIfNoMQ(t)
	ch, err := parse.ParseChannel("POSIXMQ:/socat-x")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenChannel(context.Background(), ch, xio.ModeRDWR, testGlobal())
	if err == nil {
		t.Fatal("expected POSIXMQ bidirectional error")
	}
}

func TestPOSIXMQMaxChildrenRequiresFork(t *testing.T) {
	skipIfNoMQ(t)
	ch, err := parse.ParseChannel("POSIXMQ-RECV:/socat-x,max-children=2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenChannel(context.Background(), ch, xio.ModeRead, testGlobal())
	if err == nil {
		t.Fatal("expected max-children without fork to fail")
	}
}

func TestPOSIXMQUnknownAddressNotUsed(t *testing.T) {
	skipIfNoMQ(t)
	ch, err := parse.ParseChannel("POSIXMQ-SEND:::::")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenChannel(context.Background(), ch, xio.ModeWrite, testGlobal())
	if err == nil {
		t.Fatal("expected arity error")
	}
	if bytes.Contains([]byte(err.Error()), []byte("unknown device/address")) {
		t.Fatalf("testaddrs probe must not look unknown: %v", err)
	}
}

func TestPOSIXMQEmptyMessageIsEOF(t *testing.T) {
	q := testQueue(t)
	sendMsg(t, q, "", 0)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel("POSIXMQ-READ:" + q + ",unlink-close")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(ctx, ch, xio.ModeRead, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	n, err := o.EffectiveStream().Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty MQ n=%d err=%v want EOF", n, err)
	}
}
