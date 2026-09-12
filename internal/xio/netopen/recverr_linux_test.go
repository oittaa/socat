//go:build linux

package netopen

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func closedUDP4Port(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}

func recverrTestGlobal() (*xio.Global, *bytes.Buffer) {
	var logBuf bytes.Buffer
	lg := logx.New()
	lg.SetOutput(&logBuf)
	lg.SetLevel(logx.Debug)
	return &xio.Global{BlockSize: 8192, Log: lg}, &logBuf
}

func recverrSeen(g *xio.Global, logBuf *bytes.Buffer) bool {
	if g != nil && g.SessionVar("IP_RECVERR_ERRNO") != "" {
		return true
	}
	text := logBuf.String()
	return strings.Contains(text, "IP_RECVERR") || strings.Contains(text, "received ICMP")
}

func requireRecvErrDiagnostic(t *testing.T, g *xio.Global, logBuf *bytes.Buffer, err error) {
	t.Helper()
	if recverrSeen(g, logBuf) {
		return
	}
	errno := ""
	if g != nil {
		errno = g.SessionVar("IP_RECVERR_ERRNO")
	}
	t.Fatalf("missing ICMP/IP_RECVERR diagnostic; err=%v log=%q errno=%q", err, logBuf.String(), errno)
}

func setRWDeadline(rw io.ReadWriter, d time.Time) {
	if setter, ok := rw.(interface{ SetDeadline(time.Time) error }); ok {
		_ = setter.SetDeadline(d)
	}
}

func probeStreamRecvErr(t *testing.T, st io.ReadWriter, g *xio.Global, logBuf *bytes.Buffer) {
	t.Helper()
	buf := make([]byte, 32)
	var last error
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := testutil.Until(ctx, func() (bool, error) {
		setRWDeadline(st, time.Now().Add(200*time.Millisecond))
		if _, err := st.Write([]byte("hi")); err != nil {
			last = err
		}
		if _, err := st.Read(buf); err != nil {
			last = err
		}
		return recverrSeen(g, logBuf), nil
	})
	if err != nil {
		requireRecvErrDiagnostic(t, g, logBuf, last)
	}
}

func TestUDP4SendtoRecvErrICMPLinux(t *testing.T) {
	port := closedUDP4Port(t)
	g, logBuf := recverrTestGlobal()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	o, err := xio.OpenChannel(ctx, parseChannel(t, "UDP4-SENDTO:127.0.0.1:"+strconv.Itoa(port)+",ip-recverr"), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	probeStreamRecvErr(t, o.Stream(), g, logBuf)
}

func TestUDP4DatagramRecvErrICMPLinux(t *testing.T) {
	port := closedUDP4Port(t)
	g, logBuf := recverrTestGlobal()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	o, err := xio.OpenChannel(ctx, parseChannel(t, "UDP4-DATAGRAM:127.0.0.1:"+strconv.Itoa(port)+",ip-recverr"), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	probeStreamRecvErr(t, o.Stream(), g, logBuf)
}

func openUDP4RecvErrFirst(t *testing.T, spec string, open func(context.Context, addrconfig.Address, xio.Mode, *xio.Global) (*xio.Opened, error), g *xio.Global) (*xio.Opened, *net.UDPConn) {
	t.Helper()
	parsed, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	config := mustAddr(t, parsed)
	bound := make(chan net.Addr, 1)
	restore := xio.SetListenBoundTestHook(func(addr net.Addr) {
		select {
		case bound <- addr:
		default:
		}
	})
	t.Cleanup(restore)

	errc := make(chan error, 1)
	opened := make(chan *xio.Opened, 1)
	go func() {
		o, err := open(context.Background(), config, xio.ModeRDWR, g)
		if err != nil {
			errc <- err
			return
		}
		opened <- o
	}()

	var addr net.Addr
	select {
	case addr = <-bound:
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("address did not bind")
	}
	client, err := net.DialUDP("udp4", nil, addr.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errc:
		t.Fatal(err)
	case o := <-opened:
		t.Cleanup(func() { _ = o.Close() })
		return o, client
	case <-time.After(3 * time.Second):
		t.Fatal("address did not receive the first datagram")
	}
	return nil, nil
}

func TestUDP4ListenRecvErrICMPLinux(t *testing.T) {
	g, logBuf := recverrTestGlobal()
	o, client := openUDP4RecvErrFirst(t, "UDP4-LISTEN:0,bind=127.0.0.1,ip-recverr", openUDP4Listen, g)
	buf := make([]byte, 16)
	setRWDeadline(o.Stream(), time.Now().Add(2*time.Second))
	n, err := o.Stream().Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("first payload n=%d err=%v data=%q", n, err, buf[:n])
	}
	_ = client.Close()
	probeStreamRecvErr(t, o.Stream(), g, logBuf)
}

func TestUDP4RecvfromRecvErrICMPLinux(t *testing.T) {
	g, logBuf := recverrTestGlobal()
	o, client := openUDP4RecvErrFirst(t, "UDP4-RECVFROM:0,bind=127.0.0.1,ip-recverr", openUDP4Recvfrom, g)
	buf := make([]byte, 16)
	setRWDeadline(o.Stream(), time.Now().Add(2*time.Second))
	n, err := o.Stream().Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("first payload n=%d err=%v data=%q", n, err, buf[:n])
	}
	_ = client.Close()
	probeStreamRecvErr(t, o.Stream(), g, logBuf)
}
