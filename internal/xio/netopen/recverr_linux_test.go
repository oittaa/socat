//go:build linux

package netopen

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
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
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		setRWDeadline(st, time.Now().Add(200*time.Millisecond))
		if _, err := st.Write([]byte("hi")); err != nil {
			last = err
		}
		if _, err := st.Read(buf); err != nil {
			last = err
		}
		if recverrSeen(g, logBuf) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	requireRecvErrDiagnostic(t, g, logBuf, last)
}

func probeConnRecvErr(t *testing.T, c net.Conn) {
	t.Helper()
	buf := make([]byte, 32)
	var last error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := c.Write([]byte("hi")); err != nil {
			last = err
		}
		if _, err := c.Read(buf); err != nil {
			last = err
		}
		if env := sessionEnvOf(c); env["IP_RECVERR_ERRNO"] != "" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("missing ICMP/IP_RECVERR diagnostic on fork child; last=%v env=%v", last, sessionEnvOf(c))
}

func sessionEnvOf(c net.Conn) map[string]string {
	if se, ok := c.(interface{ SessionEnvironment() map[string]string }); ok {
		return se.SessionEnvironment()
	}
	return nil
}

func enableIPRecvErr(t *testing.T, c *net.UDPConn) {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVERR, 1)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
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
	probeStreamRecvErr(t, o.Stream, g, logBuf)
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
	probeStreamRecvErr(t, o.Stream, g, logBuf)
}

func openUDP4RecvErrFirst(t *testing.T, spec string, open func(context.Context, parse.Spec, xio.Mode, *xio.Global) (*xio.Opened, error), g *xio.Global) (*xio.Opened, *net.UDPConn) {
	t.Helper()
	parsed, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
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
		o, err := open(context.Background(), parsed, xio.ModeRDWR, g)
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
	setRWDeadline(o.Stream, time.Now().Add(2*time.Second))
	n, err := o.Stream.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("first payload n=%d err=%v data=%q", n, err, buf[:n])
	}
	_ = client.Close()
	probeStreamRecvErr(t, o.Stream, g, logBuf)
}

func TestUDP4RecvfromRecvErrICMPLinux(t *testing.T) {
	g, logBuf := recverrTestGlobal()
	o, client := openUDP4RecvErrFirst(t, "UDP4-RECVFROM:0,bind=127.0.0.1,ip-recverr", openUDP4Recvfrom, g)
	buf := make([]byte, 16)
	setRWDeadline(o.Stream, time.Now().Add(2*time.Second))
	n, err := o.Stream.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("first payload n=%d err=%v data=%q", n, err, buf[:n])
	}
	_ = client.Close()
	probeStreamRecvErr(t, o.Stream, g, logBuf)
}

func TestUDP4ListenForkRecvErrICMPLinux(t *testing.T) {
	g, _ := recverrTestGlobal()
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,ip-recverr")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	client, err := net.DialUDP("udp4", nil, o.Listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	firstCh := startUDPAccept(o.Listener)
	if _, err := client.Write([]byte("pkt1")); err != nil {
		t.Fatal(err)
	}
	child := waitUDPAccept(t, firstCh, 2*time.Second, "listen fork recverr")
	t.Cleanup(func() { _ = child.Close() })

	buf := make([]byte, 16)
	n, err := child.Read(buf)
	if err != nil || string(buf[:n]) != "pkt1" {
		t.Fatalf("first payload n=%d err=%v data=%q", n, err, buf[:n])
	}
	_ = client.Close()
	probeConnRecvErr(t, child)
}

func TestUDP4RecvfromForkRecvErrICMPLinux(t *testing.T) {
	g, _ := recverrTestGlobal()
	spec, err := parse.ParseSpec("UDP4-RECVFROM:0,bind=127.0.0.1,reuseaddr,fork,ip-recverr")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Recvfrom(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	client, err := net.DialUDP("udp4", nil, o.Listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	firstCh := startUDPAccept(o.Listener)
	if _, err := client.Write([]byte("pkt1")); err != nil {
		t.Fatal(err)
	}
	child := waitUDPAccept(t, firstCh, 2*time.Second, "recvfrom fork recverr")
	t.Cleanup(func() { _ = child.Close() })

	buf := make([]byte, 16)
	n, err := child.Read(buf)
	if err != nil || string(buf[:n]) != "pkt1" {
		t.Fatalf("first payload n=%d err=%v data=%q", n, err, buf[:n])
	}
	_ = client.Close()
	probeConnRecvErr(t, child)
}

func TestUDPSessionConnRecvErrWriteLinux(t *testing.T) {
	parent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	enableIPRecvErr(t, parent)

	port := closedUDP4Port(t)
	g, logBuf := recverrTestGlobal()
	u := &udpSessionConn{
		pc:           parent,
		peer:         &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
		first:        []byte("first"),
		firstPending: true,
		oneShot:      true,
		recvErr:      true,
		g:            g,
		writeMu:      new(sync.Mutex),
	}
	buf := make([]byte, 8)
	n, err := u.Read(buf)
	if err != nil || string(buf[:n]) != "first" {
		t.Fatalf("first n=%d err=%v data=%q", n, err, buf[:n])
	}
	probeStreamRecvErr(t, u, g, logBuf)
}
