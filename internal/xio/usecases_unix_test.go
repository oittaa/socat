//go:build unix

package xio_test

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func lookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not on PATH", name)
	}
	return p
}

func TestUNIXListenPIPEEcho(t *testing.T) {
	if !xio.FeatureGENERICSOCKET && !xio.FeatureSOCKETPAIR {
		t.Skip("UNIX sockets not enabled")
	}
	ctx, g := testCtx(t), testGlobal()
	path := testutil.UnixSocketPath(t, "echo.sock")
	startForkListenPIPE(t, ctx, g, "UNIX-LISTEN:"+path+",unlink-early,fork")
	cli := openClient(t, ctx, g, "UNIX-CONNECT:"+path)
	echoLive(t, streamOf(t, cli), []byte("unix-hello"))
}

// Non-fork datagram listeners receive the first packet while opening the
// address. The relay must drain that buffered packet before polling the now
// empty socket descriptor.
func TestUDP4ListenNonForkPIPEEcho(t *testing.T) {
	ctx := testCtx(t)
	port := freeUDP4Port(t)
	done := make(chan error, 1)
	go func() {
		done <- xio.Run(ctx,
			mustParse(t, fmt.Sprintf("UDP4-LISTEN:%d,reuseaddr=0,bind=127.0.0.1", port)),
			mustParse(t, "PIPE"), cloneGlobal(nil))
	}()

	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	payload := []byte("udp-nonfork")
	buf := make([]byte, len(payload))
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := client.Read(buf)
		if err == nil {
			if string(buf[:n]) != string(payload) {
				t.Fatalf("echo got %q want %q", buf[:n], payload)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("non-fork UDP relay did not exit")
			}
			return
		}
		// A first send can beat bind and report ICMP port-unreachable on a
		// connected UDP socket. Retry until the fixed-port listener is ready.
	}
	t.Fatal("timed out waiting for non-fork UDP echo")
}

func TestUNIXRecvfromNonForkPIPEEcho(t *testing.T) {
	ctx := testCtx(t)
	serverPath := testutil.UnixSocketPath(t, "recvfrom.sock")
	clientPath := testutil.UnixSocketPath(t, "client.sock")
	done := make(chan error, 1)
	go func() {
		done <- xio.Run(ctx,
			mustParse(t, "UNIX-RECVFROM:"+serverPath+",unlink-early"),
			mustParse(t, "PIPE"), cloneGlobal(nil))
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Lstat(serverPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("UNIX-RECVFROM socket was not created")
		}
		time.Sleep(10 * time.Millisecond)
	}
	client, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: clientPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = os.Remove(clientPath)
	})
	payload := []byte("unix-nonfork")
	if _, err := client.WriteToUnix(payload, &net.UnixAddr{Name: serverPath, Net: "unixgram"}); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(payload))
	n, _, err := client.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echo got %q want %q", buf[:n], payload)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("non-fork UNIX-RECVFROM relay did not exit")
	}
}

func TestUNIXListenMode(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	path := testutil.UnixSocketPath(t, "mode.sock")
	startForkListenPIPE(t, ctx, g, "UNIX-LISTEN:"+path+",unlink-early,fork,mode=600")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %o want 0600", st.Mode().Perm())
	}
}

// TestTCPListenUnixConnect is the README docker.sock / PostgreSQL shape:
// TCP4-LISTEN,reuseaddr,fork → UNIX-CONNECT:path.
func TestTCPListenUnixConnect(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	path := testutil.UnixSocketPath(t, "app.sock")
	startForkListenPIPE(t, ctx, g, "UNIX-LISTEN:"+path+",unlink-early,fork")
	front := startListenRight(t, ctx, g,
		"TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1",
		"UNIX-CONNECT:"+path)
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, front)+",connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("tcp-to-unix"))
}

// TestUNIXListenTCPConnect is the README reverse: UNIX-LISTEN → TCP4:host:port.
func TestUNIXListenTCPConnect(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	back := startForkListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	path := testutil.UnixSocketPath(t, "app.sock")
	startListenRight(t, ctx, g,
		"UNIX-LISTEN:"+path+",unlink-early,fork,mode=600",
		"TCP4:127.0.0.1:"+tcpPort(t, back)+",connect-timeout=2")
	cli := openClient(t, ctx, g, "UNIX-CONNECT:"+path)
	echoLive(t, streamOf(t, cli), []byte("unix-to-tcp"))
}

func TestGOPENUnixSocket(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	path := testutil.UnixSocketPath(t, "gopen.sock")
	startForkListenPIPE(t, ctx, g, "UNIX-LISTEN:"+path+",unlink-early,fork")
	cli := openClient(t, ctx, g, "GOPEN:"+path)
	echoLive(t, streamOf(t, cli), []byte("gopen-unix"))
}

func TestNamedFIFO(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	path := filepath.Join(t.TempDir(), "named.fifo")
	opened := make(chan *xio.Opened, 1)
	errCh := make(chan error, 1)
	go func() {
		o, err := xio.OpenChannel(ctx, mustParse(t, "PIPE:"+path), xio.ModeRead, g)
		if err != nil {
			errCh <- err
			return
		}
		opened <- o
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(path); err == nil && st.Mode()&os.ModeNamedPipe != 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	w, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	const payload = "fifo-bytes"
	if _, err := io.WriteString(w, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		t.Fatal(err)
	case o := <-opened:
		t.Cleanup(func() { _ = o.Close() })
		if got := string(readAll(t, o.Stream)); got != payload {
			t.Fatalf("FIFO got %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("named PIPE open timed out")
	}
}

func TestEXECPrintsStdout(t *testing.T) {
	if !xio.FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	echo := lookPath(t, "echo")
	ctx, g := testCtx(t), testGlobal()
	o, err := xio.OpenChannel(ctx, mustParse(t, "EXEC:"+echo+" socat-exec-ok"), xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	got := strings.TrimSpace(string(readAll(t, o.Stream)))
	if got != "socat-exec-ok" {
		t.Fatalf("EXEC got %q", got)
	}
}

func TestSYSTEMChdir(t *testing.T) {
	if !xio.FeatureEXEC {
		t.Skip("SYSTEM not enabled")
	}
	ctx, g := testCtx(t), testGlobal()
	dir := t.TempDir()
	o, err := xio.OpenChannel(ctx, mustParse(t, "SYSTEM:pwd,chdir="+dir), xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	got := strings.TrimSpace(string(readAll(t, o.Stream)))
	gotInfo, err := os.Stat(got)
	if err != nil {
		t.Fatalf("pwd output %q: %v", got, err)
	}
	wantInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(gotInfo, wantInfo) {
		t.Fatalf("SYSTEM pwd=%q is not chdir %q", got, dir)
	}
}

func TestSHELLHonorsShell(t *testing.T) {
	if !xio.FeatureEXEC {
		t.Skip("SHELL not enabled")
	}
	ctx, g := testCtx(t), testGlobal()
	o, err := xio.OpenChannel(ctx, mustParse(t, "SHELL:printf socat-shell-ok,shell=/bin/sh"), xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if got := string(readAll(t, o.Stream)); got != "socat-shell-ok" {
		t.Fatalf("SHELL got %q", got)
	}
}

func TestSYSTEMSocketpairRoundtrip(t *testing.T) {
	if !xio.FeatureEXEC {
		t.Skip("SYSTEM not enabled")
	}
	cat := lookPath(t, "cat")
	ctx, g := testCtx(t), testGlobal()
	o, err := xio.OpenChannel(ctx, mustParse(t, "SYSTEM:"+cat), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	const payload = "abcde"
	mustWrite(t, o.Stream, []byte(payload))
	if err := o.Stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	if got := string(readFull(t, o.Stream, len(payload))); got != payload {
		t.Fatalf("SYSTEM socketpair got %q", got)
	}
}

// TestTCPListenEXECCat is the inetd shape: TCP4-LISTEN,fork EXEC:cat.
func TestTCPListenEXECCat(t *testing.T) {
	if !xio.FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	cat := lookPath(t, "cat")
	ctx, g := testCtx(t), testGlobal()
	srv := startListenRight(t, ctx, g,
		"TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1",
		"EXEC:"+cat)
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, srv)+",connect-timeout=2")
	const payload = "inetd-cat"
	mustWrite(t, cli.Stream, []byte(payload))
	if err := cli.Stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	if got := string(readFull(t, cli.Stream, len(payload))); got != payload {
		t.Fatalf("EXEC cat got %q", got)
	}
}

// TestTCPListenEXECCatEndClose is inetd with end-close: TCP4-LISTEN,fork
// EXEC:cat,end-close. Classic still uses socketpair per child.
func TestTCPListenEXECCatEndClose(t *testing.T) {
	if !xio.FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	cat := lookPath(t, "cat")
	ctx, g := testCtx(t), testGlobal()
	srv := startListenRight(t, ctx, g,
		"TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1",
		"EXEC:"+cat+",end-close")
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, srv)+",connect-timeout=2")
	const payload = "inetd-end-close"
	mustWrite(t, cli.Stream, []byte(payload))
	if err := cli.Stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	if got := string(readFull(t, cli.Stream, len(payload))); got != payload {
		t.Fatalf("EXEC cat,end-close got %q", got)
	}
}

// TestEXECEndCloseToTCPListenForkSequentialClients is the shared-FD shape:
// EXEC:cat,end-close TCP-LISTEN,fork. Two sequential clients reuse one
// socketpair; runForkListenRight serializes sessions on leftMu.
func TestEXECEndCloseToTCPListenForkSequentialClients(t *testing.T) {
	if !xio.FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	cat := lookPath(t, "cat")
	ctx, g := testCtx(t), testGlobal()
	left, err := xio.OpenChannel(ctx, mustParse(t, "EXEC:"+cat+",end-close"), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	port := freeTCP4Port(t)
	go func() {
		_ = xio.RunOpened(ctx, left, mustParse(t, fmt.Sprintf("TCP-LISTEN:%d,reuseaddr,fork,bind=127.0.0.1", port)), cloneGlobal(nil))
	}()
	for _, payload := range []string{"first-session", "second-session"} {
		cli := openClient(t, ctx, testGlobal(), fmt.Sprintf("TCP:127.0.0.1:%d,connect-timeout=2", port))
		mustWrite(t, cli.Stream, []byte(payload))
		if err := cli.Stream.ShutdownWrite(); err != nil {
			t.Fatal(err)
		}
		if got := string(readFull(t, cli.Stream, len(payload))); got != payload {
			t.Fatalf("shared EXEC,end-close got %q want %q", got, payload)
		}
		if err := cli.Stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEXECPtyRoundtrip(t *testing.T) {
	if !xio.FeatureEXEC || !xio.FeaturePTY {
		t.Skip("EXEC/PTY not enabled")
	}
	dd := lookPath(t, "dd")
	ctx, g := testCtx(t), testGlobal()
	o, err := xio.OpenChannel(ctx, mustParse(t, "EXEC:"+dd+" bs=1 count=5,pty,setsid,stderr,rawer,echo=0"), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	const payload = "abcde"
	mustWrite(t, o.Stream, []byte(payload))
	if got := string(readFull(t, o.Stream, len(payload))); got != payload {
		t.Fatalf("EXEC,pty got %q", got)
	}
}

func TestEXECfdinFdout(t *testing.T) {
	if !xio.FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	ctx, g := testCtx(t), testGlobal()
	o, err := xio.OpenChannel(ctx, mustParse(t, "SYSTEM:dd bs=1 count=5 <&3 >&4 2>/dev/null,fdin=3,fdout=4"), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	const payload = "fghij"
	mustWrite(t, o.Stream, []byte(payload))
	if got := string(readFull(t, o.Stream, len(payload))); got != payload {
		t.Fatalf("fdin/fdout got %q", got)
	}
}

func TestPTYLinkSlaveBytes(t *testing.T) {
	if !xio.FeaturePTY {
		t.Skip("PTY not enabled")
	}
	ctx, g := testCtx(t), testGlobal()
	link := filepath.Join(t.TempDir(), "pty-link")
	o, err := xio.OpenChannel(ctx, mustParse(t, "PTY,echo=0,rawer,link="+link), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	slave, err := os.OpenFile(link, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	const payload = "pty!"
	mustWrite(t, o.Stream, []byte(payload))
	buf := make([]byte, len(payload))
	_ = slave.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(slave, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != payload {
		t.Fatalf("pty slave got %q", buf)
	}
}

func TestUnixDialNetEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	path := testutil.UnixSocketPath(t, "net.sock")
	startForkListenPIPE(t, ctx, g, "UNIX-LISTEN:"+path+",unlink-early,fork")
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	echoLive(t, c, []byte("net-unix"))
}

func TestUNIXClientConnect(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	path := testutil.UnixSocketPath(t, "client.sock")
	startForkListenPIPE(t, ctx, g, "UNIX-LISTEN:"+path+",unlink-early,fork")
	cli := openClient(t, ctx, g, "UNIX-CLIENT:"+path)
	echoLive(t, streamOf(t, cli), []byte("unix-client"))
}

func TestUNIXListenEXECCat(t *testing.T) {
	if !xio.FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	cat := lookPath(t, "cat")
	ctx, g := testCtx(t), testGlobal()
	path := testutil.UnixSocketPath(t, "exec.sock")
	startListenRight(t, ctx, g, "UNIX-LISTEN:"+path+",unlink-early,fork", "EXEC:"+cat)
	cli := openClient(t, ctx, g, "UNIX-CONNECT:"+path)
	const payload = "unix-inetd"
	mustWrite(t, cli.Stream, []byte(payload))
	if err := cli.Stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	if got := string(readFull(t, cli.Stream, len(payload))); got != payload {
		t.Fatalf("UNIX-LISTEN EXEC got %q", got)
	}
}

func TestEXECPipesRoundtrip(t *testing.T) {
	if !xio.FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	cat := lookPath(t, "cat")
	ctx, g := testCtx(t), testGlobal()
	o, err := xio.OpenChannel(ctx, mustParse(t, "EXEC:"+cat+",pipes"), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	const payload = "pipes-ok"
	mustWrite(t, o.Stream, []byte(payload))
	if err := o.Stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	if got := string(readFull(t, o.Stream, len(payload))); got != payload {
		t.Fatalf("EXEC,pipes got %q", got)
	}
}

func TestSOCKETPAIREcho(t *testing.T) {
	if !xio.FeatureSOCKETPAIR {
		t.Skip("SOCKETPAIR not enabled")
	}
	ctx, g := testCtx(t), testGlobal()
	o, err := xio.OpenChannel(ctx, mustParse(t, "SOCKETPAIR"), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	echoLive(t, streamOf(t, o), []byte("socketpair"))
}

func TestUNIXSendtoRecv(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	ctx, g := testCtx(t), testGlobal()
	path := testutil.UnixSocketPath(t, "dgram.sock")
	recv, err := xio.OpenChannel(ctx, mustParse(t, "UNIX-RECV:"+path+",unlink-early"), xio.ModeRead, cloneGlobal(g))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	send, err := xio.OpenChannel(ctx, mustParse(t, "UNIX-SENDTO:"+path), xio.ModeWrite, cloneGlobal(g))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	const payload = "unix-dgram"
	mustWrite(t, send.Stream, []byte(payload))
	if got := string(readFull(t, recv.Stream, len(payload))); got != payload {
		t.Fatalf("UNIX-RECV got %q", got)
	}
}

func TestFIFOAliasNamedPipe(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	path := filepath.Join(t.TempDir(), "alias.fifo")
	opened := make(chan *xio.Opened, 1)
	errCh := make(chan error, 1)
	go func() {
		o, err := xio.OpenChannel(ctx, mustParse(t, "FIFO:"+path), xio.ModeRead, cloneGlobal(g))
		if err != nil {
			errCh <- err
			return
		}
		opened <- o
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(path); err == nil && st.Mode()&os.ModeNamedPipe != 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	w, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	const payload = "fifo-alias"
	if _, err := io.WriteString(w, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		t.Fatal(err)
	case o := <-opened:
		t.Cleanup(func() { _ = o.Close() })
		if got := string(readAll(t, o.Stream)); got != payload {
			t.Fatalf("FIFO alias got %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("FIFO alias open timed out")
	}
}
