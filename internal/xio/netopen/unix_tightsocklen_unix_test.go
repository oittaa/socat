//go:build unix

package netopen

import (
	"context"
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
