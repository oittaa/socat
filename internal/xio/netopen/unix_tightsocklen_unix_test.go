//go:build unix

package netopen

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestUnixTightSocklenListenConnect(t *testing.T) {
	for _, extra := range []string{"", ",unix-tightsocklen=1", ",tightsocklen=0"} {
		t.Run("opt"+extra, func(t *testing.T) {
			path := unixSocketTestPath(t, "tight.sock")
			lspec, err := parse.ParseSpec("UNIX-LISTEN:" + path + extra + ",fork")
			if err != nil {
				t.Fatal(err)
			}
			server, err := openUnixListen(context.Background(), lspec, xio.ModeRDWR, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })

			done := make(chan error, 1)
			go func() {
				c, err := server.Listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer func() { _ = c.Close() }()
				buf := make([]byte, 8)
				n, err := c.Read(buf)
				if err != nil {
					done <- err
					return
				}
				_, err = c.Write(buf[:n])
				done <- err
			}()

			cspec, err := parse.ParseSpec("UNIX-CONNECT:" + path + extra)
			if err != nil {
				t.Fatal(err)
			}
			client, err := openUnixConnect(context.Background(), cspec, xio.ModeRDWR, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if _, err := client.Stream.Write([]byte("hi")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 8)
			n, err := client.Stream.Read(buf)
			if err != nil && err != io.EOF {
				t.Fatal(err)
			}
			if string(buf[:n]) != "hi" {
				t.Fatalf("got %q", buf[:n])
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("accept/echo timed out")
			}
		})
	}
}

func TestClassicUnixSockaddrLenMatchesThisPlatform(t *testing.T) {
	sizeofUn := unix.SizeofSockaddrUnix
	sunPath := len(unix.RawSockaddrUnix{}.Path)
	if got := classicUnixSockaddrLen(5, sunPath, sizeofUn, false, false); got != sizeofUn {
		t.Fatalf("untight=%d want sizeof=%d", got, sizeofUn)
	}
}

func TestUnixRawSockaddrUsesClassicLen(t *testing.T) {
	sizeofUn := unix.SizeofSockaddrUnix
	sunPath := len(unix.RawSockaddrUnix{}.Path)
	_, n, err := unixRawSockaddr("hello", true)
	if err != nil {
		t.Fatal(err)
	}
	want := classicUnixSockaddrLen(len("hello"), sunPath, sizeofUn, false, true)
	if n != want {
		t.Fatalf("pathname tight=%d want %d (Go net includes a terminator)", n, want)
	}
	_, n, err = unixRawSockaddr("hello", false)
	if err != nil {
		t.Fatal(err)
	}
	if n != sizeofUn {
		t.Fatalf("pathname untight=%d want %d", n, sizeofUn)
	}
	_, n, err = unixRawSockaddr("\x00abc", true)
	if err != nil {
		t.Fatal(err)
	}
	want = classicUnixSockaddrLen(3, sunPath, sizeofUn, true, true)
	if n != want {
		t.Fatalf("abstract tight=%d want %d", n, want)
	}
}

func TestUnixConnectHonorsCanceledContext(t *testing.T) {
	path := unixSocketTestPath(t, "cancel.sock")
	spec, err := parse.ParseSpec("UNIX-CONNECT:" + path)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := listenUnixNetwork(context.Background(), spec, "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := dialUnixSocklen(ctx, spec, nil, "unix", path, "")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
}
