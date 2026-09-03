//go:build linux

package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

func dialClosedUDP4(t *testing.T) *net.UDPConn {
	t.Helper()
	closed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := closed.LocalAddr().(*net.UDPAddr)
	_ = closed.Close()
	c, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func connFD(t *testing.T, c syscall.Conn) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	fd := -1
	if err := raw.Control(func(rawFD uintptr) { fd = int(rawFD) }); err != nil {
		t.Fatal(err)
	}
	if fd < 0 {
		t.Fatal("no fd")
	}
	return fd
}

func isConnRefused(err error) bool {
	return err != nil && (errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "connection refused"))
}

func TestWaitPollReadUDPErrorIsNotEOF(t *testing.T) {
	conn := dialClosedUDP4(t)
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	fd := connFD(t, conn)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for UDP POLLERR")
		}
		err := waitPollRead(fd, 50)
		if err == io.EOF {
			t.Fatal("POLLERR became EOF; Read would never see the ICMP error")
		}
		if err == errPollIdle {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	_, err := conn.Read(make([]byte, 16))
	if !isConnRefused(err) {
		t.Fatalf("read after POLLERR err=%v want connection refused", err)
	}
}

func TestSessionWrapReadDeliversUDPError(t *testing.T) {
	conn := dialClosedUDP4(t)
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	w := newSessionWrap(NetStream{Conn: conn})
	done := make(chan error, 1)
	go func() {
		_, err := w.Read(make([]byte, 16))
		done <- err
	}()
	select {
	case err := <-done:
		if err == io.EOF {
			t.Fatal("sessionWrap.Read turned POLLERR into EOF")
		}
		if !isConnRefused(err) {
			t.Fatalf("sessionWrap.Read err=%v want connection refused", err)
		}
	case <-time.After(2 * time.Second):
		_ = w.Close()
		t.Fatal("sessionWrap.Read timed out")
	}
}

func TestTransferEndCloseUDPPollErrIsNotEOF(t *testing.T) {
	conn := dialClosedUDP4(t)
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- Transfer(context.Background(),
			FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}},
			testEndClose{Stream: NetStream{Conn: conn}},
			Config{
				LeftToRight:  false,
				RightToLeft:  true,
				NoCloseRight: true,
				Linger:       200 * time.Millisecond,
			})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("end-close treated UDP POLLERR as clean EOF")
		}
		if !isConnRefused(err) {
			t.Fatalf("err=%v want connection refused", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("transfer timed out")
	}
}
