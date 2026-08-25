//go:build unix

package all

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	path := filepath.Join(t.TempDir(), "echo.sock")
	startListenPIPE(t, ctx, g, "UNIX-LISTEN:"+path+",unlink-early,fork")
	cli := openClient(t, ctx, g, "UNIX-CONNECT:"+path)
	echoLive(t, streamOf(t, cli), []byte("unix-hello"))
}

func TestUNIXListenMode(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	path := filepath.Join(t.TempDir(), "mode.sock")
	startListenPIPE(t, ctx, g, "UNIX-LISTEN:"+path+",unlink-early,fork,mode=600")
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
	path := filepath.Join(t.TempDir(), "app.sock")
	startListenPIPE(t, ctx, g, "UNIX-LISTEN:"+path+",unlink-early,fork")
	front := startListenRight(t, ctx, g,
		"TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1",
		"UNIX-CONNECT:"+path)
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, front)+",connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("tcp-to-unix"))
}

// TestUNIXListenTCPConnect is the README reverse: UNIX-LISTEN → TCP4:host:port.
func TestUNIXListenTCPConnect(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	back := startListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	path := filepath.Join(t.TempDir(), "app.sock")
	startListenRight(t, ctx, g,
		"UNIX-LISTEN:"+path+",unlink-early,fork,mode=600",
		"TCP4:127.0.0.1:"+tcpPort(t, back)+",connect-timeout=2")
	cli := openClient(t, ctx, g, "UNIX-CONNECT:"+path)
	echoLive(t, streamOf(t, cli), []byte("unix-to-tcp"))
}

func TestGOPENUnixSocket(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	path := filepath.Join(t.TempDir(), "gopen.sock")
	startListenPIPE(t, ctx, g, "UNIX-LISTEN:"+path+",unlink-early,fork")
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
	path := filepath.Join(t.TempDir(), "net.sock")
	startListenPIPE(t, ctx, g, "UNIX-LISTEN:"+path+",unlink-early,fork")
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	echoLive(t, c, []byte("net-unix"))
}
