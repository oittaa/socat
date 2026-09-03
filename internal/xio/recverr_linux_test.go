//go:build linux

package xio

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplyRecvErrEnableDisableLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	on, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-recverr")
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRecvErrSockopt(fd, on.Options[0]); err != nil {
		t.Fatal(err)
	}
	got, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR)
	if err != nil {
		t.Fatal(err)
	}
	if got == 0 {
		t.Fatal("IP_RECVERR still 0 after ip-recverr")
	}
	off, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-recverr=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRecvErrSockopt(fd, off.Options[0]); err != nil {
		t.Fatal(err)
	}
	got, err = unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("IP_RECVERR=%d after ip-recverr=0", got)
	}
}

func TestApplyRecvErrIntegerTwoLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-recverr=2")
	if err != nil {
		t.Fatal(err)
	}
	if !NeedRecvErr(spec) {
		t.Fatal("ip-recverr=2 should enable error-queue drain")
	}
	if err := applyRecvErrSockopt(fd, spec.Options[0]); err != nil {
		t.Fatal(err)
	}
	got, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR)
	if err != nil {
		t.Fatal(err)
	}
	if got == 0 {
		t.Fatal("IP_RECVERR still 0 after ip-recverr=2")
	}
}

func TestApplyRecvErrOnIPv6SocketLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("UDP6:[::1]:1,ip-recverr")
	if err != nil {
		t.Fatal(err)
	}
	if err := RejectUnsupportedRecvErr(spec); err != nil {
		t.Fatalf("ip-recverr on UDP6: %v", err)
	}
	if err := applyRecvErrSockopt(fd, spec.Options[0]); err != nil {
		t.Fatal(err)
	}
	got, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR)
	if err != nil {
		t.Fatal(err)
	}
	if got == 0 {
		t.Fatal("IP_RECVERR still 0 on IPv6 socket")
	}
}

func TestApplyRecvErrOnTCPLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("TCP:127.0.0.1:1,ip-recverr")
	if err != nil {
		t.Fatal(err)
	}
	if err := RejectUnsupportedRecvErr(spec); err != nil {
		t.Fatalf("ip-recverr on TCP: %v", err)
	}
	if err := applyRecvErrSockopt(fd, spec.Options[0]); err != nil {
		t.Fatal(err)
	}
	got, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR)
	if err != nil {
		t.Fatal(err)
	}
	if got == 0 {
		t.Fatal("IP_RECVERR still 0 on TCP")
	}
}

func TestDrainRecvErrEmptyQueueLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
		t.Fatal(err)
	}
	drainRecvErrQueue(fd, &Global{Log: logx.New()})
}

func TestHandleIPRecvErrTruncatedCmsgLinux(t *testing.T) {
	g := &Global{Log: logx.New(), SessionVars: map[string]string{}}
	handleIPRecvErrCmsg([]byte{1, 2, 3}, g)
	if len(g.SessionVars) != 0 {
		t.Fatalf("truncated cmsg set env %v", g.SessionVars)
	}
}

func TestUDPConnectRecvErrICMPLinux(t *testing.T) {
	closed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := closed.LocalAddr().(*net.UDPAddr).Port
	_ = closed.Close()

	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-recverr")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	conn, ok := c.(*net.UDPConn)
	if !ok {
		t.Fatalf("Dial type %T", c)
	}

	var logBuf bytes.Buffer
	lg := logx.New()
	lg.SetOutput(&logBuf)
	lg.SetLevel(logx.Debug)
	g := &Global{Log: lg}
	wrapped := WrapUDPAncillary(conn, spec, g)

	if _, err := wrapped.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if wc, ok := wrapped.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = wc.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
	buf := make([]byte, 16)
	_, err = wrapped.Read(buf)
	if err == nil {
		t.Fatal("expected ICMP/error-queue read failure")
	}
	if !errors.Is(err, unix.ECONNREFUSED) && !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("read err=%v want connection refused", err)
	}
	if g.SessionVar("IP_RECVERR_ERRNO") == "" && !strings.Contains(logBuf.String(), "IP_RECVERR") && !strings.Contains(logBuf.String(), "received ICMP") {
		t.Fatalf("no recverr diagnostics; err=%v log=%q errno=%q", err, logBuf.String(), g.SessionVar("IP_RECVERR_ERRNO"))
	}
}

func TestRecvErrDoesNotTurnPayloadIntoEOFLinux(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-recverr")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	uc, ok := c.(*net.UDPConn)
	if !ok {
		t.Fatalf("Dial type %T", c)
	}
	wrapped := WrapUDPAncillary(uc, spec, &Global{Log: logx.New()})
	if _, err := server.WriteTo([]byte("ok"), uc.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if wc, ok := wrapped.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = wc.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
	buf := make([]byte, 8)
	n, err := wrapped.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ok" {
		t.Fatalf("payload=%q", buf[:n])
	}
}

func TestRecvErrZeroOmitsDiagnosticsLinux(t *testing.T) {
	closed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := closed.LocalAddr().(*net.UDPAddr).Port
	_ = closed.Close()

	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-recverr=0")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	conn, ok := c.(*net.UDPConn)
	if !ok {
		t.Fatalf("Dial type %T", c)
	}
	if _, wrapped := WrapUDPAncillary(conn, spec, &Global{}).(*udpAncillaryConn); wrapped {
		t.Fatal("ip-recverr=0 must not wrap the UDP connection")
	}

	var logBuf bytes.Buffer
	lg := logx.New()
	lg.SetOutput(&logBuf)
	lg.SetLevel(logx.Debug)
	g := &Global{Log: lg}
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 16))
	if err == nil {
		t.Fatal("expected connection refused without recverr diagnostics")
	}
	if g.SessionVar("IP_RECVERR_ERRNO") != "" || strings.Contains(logBuf.String(), "IP_RECVERR") || strings.Contains(logBuf.String(), "received ICMP") {
		t.Fatalf("ip-recverr=0 produced diagnostics; err=%v log=%q errno=%q", err, logBuf.String(), g.SessionVar("IP_RECVERR_ERRNO"))
	}
}

func TestHandleIPRecvErrCmsgConcurrentLinux(t *testing.T) {
	g := &Global{Log: logx.New()}
	data := make([]byte, 16)
	binary.NativeEndian.PutUint32(data[0:4], uint32(unix.ECONNREFUSED))
	data[4] = unix.SO_EE_ORIGIN_ICMP
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			handleIPRecvErrCmsg(data, g)
		}()
		go func() {
			defer wg.Done()
			_ = g.SessionVar("IP_RECVERR_ERRNO")
			_ = g.SessionVarsSnapshot()
			_ = sessionEnv(g)
		}()
	}
	wg.Wait()
	if g.SessionVar("IP_RECVERR_ERRNO") == "" {
		t.Fatal("missing IP_RECVERR_ERRNO after concurrent cmsg updates")
	}
}

func TestRecvErrSessionVarsConcurrentReadWriteLinux(t *testing.T) {
	closed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := closed.LocalAddr().(*net.UDPAddr).Port
	_ = closed.Close()

	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-recverr")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	conn, ok := c.(*net.UDPConn)
	if !ok {
		t.Fatalf("Dial type %T", c)
	}
	g := &Global{Log: logx.New()}
	wrapped := WrapUDPAncillary(conn, spec, g)
	if _, err := wrapped.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if wc, ok := wrapped.(interface{ SetReadDeadline(time.Time) error }); ok {
				_ = wc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			}
			_, _ = wrapped.Read(make([]byte, 16))
			_ = g.SessionVar("IP_RECVERR_ERRNO")
			_ = g.SessionVarsSnapshot()
		}()
		go func() {
			defer wg.Done()
			if wc, ok := wrapped.(interface{ SetWriteDeadline(time.Time) error }); ok {
				_ = wc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			}
			_, _ = wrapped.Write([]byte("x"))
			_ = g.SessionVar("IP_RECVERR_ORIGIN")
			_ = sessionEnv(g)
		}()
	}
	wg.Wait()
}
