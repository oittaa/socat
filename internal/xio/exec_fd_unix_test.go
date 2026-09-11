//go:build linux || darwin

package xio

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openEXECSpec(t *testing.T, specText string, mode Mode) *Opened {
	t.Helper()
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	spec, err := parse.ParseSpec(specText)
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenSpec(context.Background(), spec, mode, &Global{Log: logx.New(), Linger: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func readStreamBytes(t *testing.T, r io.Reader, d time.Duration) []byte {
	t.Helper()
	if f, ok := r.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = f.SetReadDeadline(time.Now().Add(d))
	}
	done := make(chan struct {
		b   []byte
		err error
	}, 1)
	go func() {
		b, err := io.ReadAll(r)
		done <- struct {
			b   []byte
			err error
		}{b, err}
	}()
	select {
	case got := <-done:
		if got.err != nil && len(got.b) == 0 {
			t.Fatalf("read stream: %v", got.err)
		}
		return got.b
	case <-time.After(d + time.Second):
		t.Fatal("timed out reading stream")
		return nil
	}
}

func captureInheritedStdout(t *testing.T, run func()) string {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = pw
	defer func() {
		os.Stdout = old
		_ = pw.Close()
		_ = pr.Close()
	}()
	run()
	os.Stdout = old
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	got := string(readStreamBytes(t, pr, 3*time.Second))
	_ = pr.Close()
	return got
}

func TestOpenSpecFDInOnlyModeWriteUnix(t *testing.T) {
	const payload = "hello"
	got := captureInheritedStdout(t, func() {
		o := openEXECSpec(t, "SYSTEM:cat <&3,fdin=3", ModeWrite)
		if _, err := o.Stream.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		if err := o.Stream.ShutdownWrite(); err != nil {
			t.Fatal(err)
		}
	})
	if got != payload {
		t.Fatalf("got %q want %q", got, payload)
	}
}

func TestOpenSpecStderrCustomFDOutUnix(t *testing.T) {
	var inherited, relayed string
	inherited = captureInheritedStdout(t, func() {
		o := openEXECSpec(t, "SYSTEM:printf O; printf D >&4; printf E >&2,fdin=3,fdout=4,stderr", ModeRDWR)
		relayed = string(readStreamBytes(t, o.Stream, 3*time.Second))
	})
	if inherited != "O" {
		t.Fatalf("inherited stdout %q want O", inherited)
	}
	if relayed != "DE" {
		t.Fatalf("relayed %q want DE", relayed)
	}
}

func TestOpenSpecStderrHighFDOutUnix(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash not available")
	}
	var inherited, relayed string
	inherited = captureInheritedStdout(t, func() {
		o := openEXECSpec(t, "EXEC:/bin/bash -c \\\"printf O; printf D >&10; printf E >&2\\\",fdin=9,fdout=10,stderr", ModeRDWR)
		relayed = string(readStreamBytes(t, o.Stream, 3*time.Second))
	})
	if inherited != "O" {
		t.Fatalf("inherited stdout %q want O", inherited)
	}
	if relayed != "DE" {
		t.Fatalf("relayed %q want DE", relayed)
	}
}

func TestOpenSpecChdirWithFDInFDOutUnix(t *testing.T) {
	dir := t.TempDir()
	got := captureInheritedStdout(t, func() {
		_ = openEXECSpec(t, "SYSTEM:pwd,chdir="+dir+",fdin=3,fdout=4", ModeRDWR)
	})
	got = strings.TrimSpace(got)
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		want = dir
	}
	gotEval, err := filepath.EvalSymlinks(got)
	if err != nil {
		gotEval = got
	}
	if gotEval != want {
		t.Fatalf("pwd %q want %q", got, dir)
	}
}

func TestOpenSpecChdirWithHighFDOutUnix(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash not available")
	}
	dir := t.TempDir()
	o := openEXECSpec(t, "EXEC:/bin/bash -c \\\"pwd >&10\\\",chdir="+dir+",fdout=10", ModeRead)
	got := strings.TrimSpace(string(readStreamBytes(t, o.Stream, 3*time.Second)))
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		want = dir
	}
	gotEval, err := filepath.EvalSymlinks(got)
	if err != nil {
		gotEval = got
	}
	if gotEval != want {
		t.Fatalf("pwd %q want %q", got, dir)
	}
}

func TestOpenSpecEXECSocktypeDgramUnix(t *testing.T) {
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skip("/bin/cat not available")
	}
	const payload = "hello"
	got := captureInheritedStdout(t, func() {
		o := openEXECSpec(t, "EXEC:/bin/cat,socktype="+strconv.Itoa(syscall.SOCK_DGRAM), ModeWrite)
		if _, err := o.Stream.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		if err := o.Stream.ShutdownWrite(); err != nil {
			t.Fatal(err)
		}
	})
	if got != payload {
		t.Fatalf("got %q want %q", got, payload)
	}
}

func parentSocketType(t *testing.T, o *Opened) (int, error) {
	t.Helper()
	f := asOSFile(o.Stream)
	if f == nil {
		t.Fatal("parent EXEC stream has no *os.File")
	}
	sc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var typ int
	var sockErr error
	if err := sc.Control(func(fd uintptr) {
		typ, sockErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
	}); err != nil {
		return 0, err
	}
	return typ, sockErr
}

func TestOpenSpecEXECEndCloseUsesSocketpairUnix(t *testing.T) {
	// EXEC:true uses PATH. macOS has /usr/bin/true and no /bin/true.
	o := openEXECSpec(t, "EXEC:true,end-close", ModeRDWR)
	typ, err := parentSocketType(t, o)
	if err != nil {
		t.Fatalf("end-close parent is not a socket: %v", err)
	}
	if typ != syscall.SOCK_STREAM {
		t.Fatalf("end-close SO_TYPE=%d want SOCK_STREAM", typ)
	}
}

func TestOpenSpecEXECPipesIsNotSocketUnix(t *testing.T) {
	o := openEXECSpec(t, "EXEC:true,pipes", ModeRDWR)
	if _, err := parentSocketType(t, o); err == nil {
		t.Fatal("pipes parent unexpectedly is a socket")
	}
}

func noForkPipePeer(t *testing.T) (peer relay.Stream, inW, outR, outW *os.File) {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err = os.Pipe()
	if err != nil {
		_ = inR.Close()
		_ = inW.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = inR.Close()
		_ = inW.Close()
		_ = outR.Close()
		_ = outW.Close()
	})
	return relay.FDStream{R: inR, W: outW, C: NopCloser{}}, inW, outR, outW
}

func parseNoForkSpec(t *testing.T, spec string) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func runPreparedNoFork(t *testing.T, peer relay.Stream, s parse.Spec, g *Global, mode Mode) {
	t.Helper()
	prepared, err := PrepareSpec(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := runExecNoFork(context.Background(), peer, s, prepared.Config, g, mode); err != nil {
		t.Fatal(err)
	}
}

func TestRunExecNoForkTrueWithCustomFDsUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	peer, _, _, _ := noForkPipePeer(t)
	s := parseNoForkSpec(t, "EXEC:true,nofork,fdin=3,fdout=4")
	g := &Global{Log: logx.New()}
	runPreparedNoFork(t, peer, s, g, ModeRDWR)
	if g.ChildExitCode != 0 {
		t.Fatalf("EXEC:true ChildExitCode=%d want 0 (helper must LookPath the basename)", g.ChildExitCode)
	}
}

func TestRunExecNoForkTargetExit127Unix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	script := filepath.Join(t.TempDir(), "exit127")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 127\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	peer, _, _, _ := noForkPipePeer(t)
	s := parseNoForkSpec(t, "EXEC:"+script+",nofork,fdin=3,fdout=4")
	g := &Global{Log: logx.New()}
	runPreparedNoFork(t, peer, s, g, ModeRDWR)
	if g.ChildExitCode != 127 {
		t.Fatalf("target exit 127: ChildExitCode=%d want 127", g.ChildExitCode)
	}
}

func TestRunExecNoForkDashRewritesTargetArgv0Unix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	bin := buildArgv0Helper(t)
	peer, _, _, _ := noForkPipePeer(t)
	got := strings.TrimSpace(captureInheritedStdout(t, func() {
		s := parseNoForkSpec(t, "EXEC:"+bin+",dash,nofork,fdin=3,fdout=4")
		runPreparedNoFork(t, peer, s, nil, ModeRDWR)
	}))
	if got != "x-argv0" {
		t.Fatalf("nofork dash argv0=%q want x-argv0", got)
	}
}
