//go:build linux || darwin

package xio_test

import (
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

func unixChdirWorkDirs(t *testing.T) (work, chdirDir, listen string) {
	t.Helper()
	listen = testutil.UnixSocketPath(t, "server.sock")
	chdirDir = filepath.Dir(listen)
	work = filepath.Dir(testutil.UnixSocketPath(t, "work.sock"))
	t.Chdir(work)
	return work, chdirDir, listen
}

func assertBindInChdirDir(t *testing.T, work, chdirDir, bindName string) {
	t.Helper()
	want := filepath.Join(chdirDir, bindName)
	if _, err := os.Lstat(want); err != nil {
		t.Fatalf("bind path missing in chdir directory %q: %v", want, err)
	}
	if _, err := os.Lstat(filepath.Join(work, bindName)); err == nil {
		t.Fatalf("bind path %q created in original working directory", bindName)
	}
}

func TestUNIXConnectIPLiteralBindFollowsChdir(t *testing.T) {
	if !xio.FeatureGENERICSOCKET && !xio.FeatureSOCKETPAIR {
		t.Skip("UNIX sockets not enabled")
	}
	work, chdirDir, listen := unixChdirWorkDirs(t)
	ctx, g := testCtx(t), testGlobal()
	startForkListenPIPE(t, ctx, g, "UNIX-LISTEN:"+listen+",unlink-early,fork")
	cli := openClient(t, ctx, g, "UNIX-CONNECT:server.sock,bind=127.0.0.1,unlink-close=0,chdir="+chdirDir)
	assertBindInChdirDir(t, work, chdirDir, "127.0.0.1")
	echoLive(t, streamOf(t, cli), []byte("unix-chdir-ip-bind"))
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
