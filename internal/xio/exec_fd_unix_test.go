//go:build unix

package xio

import (
	"context"
	"fmt"
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

func TestOpenSpecEXECUnidirectionalCatUnix(t *testing.T) {
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skip("/bin/cat not available")
	}
	const payload = "hello"

	t.Run("mode-read-inherit-stdin", func(t *testing.T) {
		pr, pw, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdin
		os.Stdin = pr
		t.Cleanup(func() {
			os.Stdin = old
			_ = pw.Close()
			_ = pr.Close()
		})
		if _, err := pw.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		if err := pw.Close(); err != nil {
			t.Fatal(err)
		}
		o := openEXECSpec(t, "EXEC:/bin/cat", ModeRead)
		got := string(readStreamBytes(t, o.Stream, 3*time.Second))
		if got != payload {
			t.Fatalf("got %q want %q", got, payload)
		}
	})

	t.Run("mode-write-inherit-stdout", func(t *testing.T) {
		pr, pw, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdout
		os.Stdout = pw
		t.Cleanup(func() {
			os.Stdout = old
			_ = pw.Close()
			_ = pr.Close()
		})
		o := openEXECSpec(t, "EXEC:/bin/cat", ModeWrite)
		if _, err := o.Stream.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		if err := o.Stream.ShutdownWrite(); err != nil {
			t.Fatal(err)
		}
		os.Stdout = old
		if err := pw.Close(); err != nil {
			t.Fatal(err)
		}
		got := string(readStreamBytes(t, pr, 3*time.Second))
		if got != payload {
			t.Fatalf("got %q want %q", got, payload)
		}
	})
}

func TestOpenSpecFDInFDOutInheritStdoutUnix(t *testing.T) {
	tests := []struct {
		name string
		spec string
		skip func() bool
	}{
		{name: "socketpair", spec: "SYSTEM:printf O; printf D >&4,fdin=3,fdout=4"},
		{name: "pipes", spec: "SYSTEM:printf O; printf D >&4,pipes,fdin=3,fdout=4"},
		{name: "pipes-overlap-fdin4-fdout5", spec: "SYSTEM:printf O; printf D >&5,pipes,fdin=4,fdout=5"},
		{name: "pipes-overlap-swap-fdin4-fdout3", spec: "SYSTEM:printf O; printf D >&3,pipes,fdin=4,fdout=3"},
		{name: "socketpair-high-fdout", spec: "EXEC:/bin/bash -c \\\"printf O; printf D >&10\\\",fdin=9,fdout=10"},
		{name: "pipes-high-fdout", spec: "EXEC:/bin/bash -c \\\"printf O; printf D >&10\\\",pipes,fdin=9,fdout=10"},
		{name: "pty", spec: "SYSTEM:printf O; printf D >&4,pty,fdin=3,fdout=4,raw,echo=0", skip: func() bool { return !FeaturePTY }},
		{name: "pty-high-fdout", spec: "EXEC:/bin/bash -c \\\"printf O; printf D >&10\\\",pty,fdin=9,fdout=10,raw,echo=0", skip: func() bool { return !FeaturePTY }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != nil && tc.skip() {
				t.Skip("PTY not enabled")
			}
			var inherited, relayed string
			inherited = captureInheritedStdout(t, func() {
				o := openEXECSpec(t, tc.spec, ModeRDWR)
				relayed = string(readStreamBytes(t, o.Stream, 3*time.Second))
			})
			if inherited != "O" {
				t.Fatalf("inherited stdout %q want O", inherited)
			}
			if relayed != "D" {
				t.Fatalf("relayed fdout %q want D", relayed)
			}
		})
	}
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

func TestOpenSpecFDOutOnlyModeReadUnix(t *testing.T) {
	const payload = "hello"
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = pr
	t.Cleanup(func() {
		os.Stdin = old
		_ = pw.Close()
		_ = pr.Close()
	})
	if _, err := pw.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	o := openEXECSpec(t, "SYSTEM:cat >&4,fdout=4", ModeRead)
	got := string(readStreamBytes(t, o.Stream, 3*time.Second))
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

func TestOpenSpecFDInFDOutHighDescriptorsUnix(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash not available")
	}
	const payload = "high-fd-payload"
	for _, tc := range []struct {
		name string
		spec string
	}{
		{name: "socketpair", spec: "EXEC:/bin/bash -c \\\"cat <&9 >&10\\\",fdin=9,fdout=10"},
		{name: "pipes", spec: "EXEC:/bin/bash -c \\\"cat <&9 >&10\\\",pipes,fdin=9,fdout=10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := openEXECSpec(t, tc.spec, ModeRDWR)
			if _, err := o.Stream.Write([]byte(payload)); err != nil {
				t.Fatal(err)
			}
			if err := o.Stream.ShutdownWrite(); err != nil {
				t.Fatal(err)
			}
			if got := string(readStreamBytes(t, o.Stream, 3*time.Second)); got != payload {
				t.Fatalf("relayed %q want %q", got, payload)
			}
		})
	}
}

func TestOpenSpecPipesSameFDInputWinsUnix(t *testing.T) {
	script := filepath.Join(t.TempDir(), "same-fd.sh")
	body := "#!/bin/sh\nIFS= read -r line <&5\nprintf '%s' \"$line\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	got := captureInheritedStdout(t, func() {
		o := openEXECSpec(t, "EXEC:"+script+",pipes,fdin=5,fdout=5", ModeRDWR)
		if _, err := o.Stream.Write([]byte("input-wins\n")); err != nil {
			t.Fatal(err)
		}
		if err := o.Stream.ShutdownWrite(); err != nil {
			t.Fatal(err)
		}
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
	})
	if got != "input-wins" {
		t.Fatalf("inherited stdout=%q want input-wins", got)
	}
}

func TestOpenSpecChildHelperFDsClosedUnix(t *testing.T) {
	script := filepath.Join(t.TempDir(), "fds.sh")
	// /dev/fd works on Linux and Darwin; /proc/self/fd is Linux-only.
	body := "#!/bin/sh\ni=0\nwhile [ \"$i\" -le 32 ]; do\n  if [ -e /dev/fd/$i ]; then echo $i; fi\n  i=$((i+1))\ndone\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	out := captureInheritedStdout(t, func() {
		_ = openEXECSpec(t, "SYSTEM:"+script+",fdin=7,fdout=8", ModeRDWR)
	})
	seen := map[int]bool{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		n, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
		seen[n] = true
	}
	if !seen[7] || !seen[8] {
		t.Fatalf("missing fdin/fdout in %v", seen)
	}
	if seen[4] {
		t.Fatalf("helper ExtraFiles fd 4 leaked: %v", seen)
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

func TestOpenSpecNoForkValidatesFDOptionsUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	tests := []struct {
		spec string
		mode Mode
		want string
	}{
		{spec: "EXEC:true,nofork,fdin=3", mode: ModeRead, want: "fdin"},
		{spec: "EXEC:true,nofork,fdout=4", mode: ModeWrite, want: "fdout"},
		{spec: "EXEC:true,nofork,fdin=65536", mode: ModeRDWR, want: "unsigned-short range"},
		{spec: "EXEC:true,nofork,fdout=65536", mode: ModeRDWR, want: "unsigned-short range"},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			o, err := OpenSpec(context.Background(), spec, tc.mode, &Global{Log: logx.New(), Linger: time.Second})
			if err == nil {
				_ = o.Close()
				t.Fatalf("accepted %s", tc.spec)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want substring %q", err, tc.want)
			}
		})
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

func TestRunExecNoForkFDInFDOutInheritUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	peer, _, outR, outW := noForkPipePeer(t)
	var relayed string
	inherited := captureInheritedStdout(t, func() {
		s := parseNoForkSpec(t, "SYSTEM:printf O; printf D >&4,nofork,fdin=3,fdout=4")
		if err := runExecNoFork(context.Background(), peer, s, nil, ModeRDWR); err != nil {
			t.Fatal(err)
		}
		_ = outW.Close()
		relayed = string(readStreamBytes(t, outR, 3*time.Second))
	})
	if inherited != "O" {
		t.Fatalf("inherited stdout %q want O", inherited)
	}
	if relayed != "D" {
		t.Fatalf("relayed fdout %q want D", relayed)
	}
}

func TestRunExecNoForkFDInFDOutHighDescriptorsUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash not available")
	}
	const payload = "high-fd-payload"
	peer, inW, outR, outW := noForkPipePeer(t)
	if _, err := inW.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := inW.Close(); err != nil {
		t.Fatal(err)
	}
	s := parseNoForkSpec(t, "EXEC:/bin/bash -c \\\"cat <&9 >&10\\\",nofork,fdin=9,fdout=10")
	if err := runExecNoFork(context.Background(), peer, s, nil, ModeRDWR); err != nil {
		t.Fatal(err)
	}
	_ = outW.Close()
	if got := string(readStreamBytes(t, outR, 3*time.Second)); got != payload {
		t.Fatalf("relayed %q want %q", got, payload)
	}
}

func TestRunExecNoForkFDInOnlyModeWriteUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	const payload = "hello"
	peer, inW, _, _ := noForkPipePeer(t)
	if _, err := inW.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := inW.Close(); err != nil {
		t.Fatal(err)
	}
	got := captureInheritedStdout(t, func() {
		s := parseNoForkSpec(t, "SYSTEM:cat <&3,nofork,fdin=3")
		if err := runExecNoFork(context.Background(), peer, s, nil, ModeWrite); err != nil {
			t.Fatal(err)
		}
	})
	if got != payload {
		t.Fatalf("inherited stdout %q want %q", got, payload)
	}
}

func TestRunExecNoForkFDOutOnlyModeReadUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	const payload = "hello"
	peer, _, outR, outW := noForkPipePeer(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = pr
	t.Cleanup(func() {
		os.Stdin = old
		_ = pw.Close()
		_ = pr.Close()
	})
	if _, err := pw.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	s := parseNoForkSpec(t, "SYSTEM:cat >&4,nofork,fdout=4")
	if err := runExecNoFork(context.Background(), peer, s, nil, ModeRead); err != nil {
		t.Fatal(err)
	}
	_ = outW.Close()
	if got := string(readStreamBytes(t, outR, 3*time.Second)); got != payload {
		t.Fatalf("relayed %q want %q", got, payload)
	}
}

func TestRunExecNoForkStderrCustomFDOutUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	peer, _, outR, outW := noForkPipePeer(t)
	oldErr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = oldErr
		_ = w.Close()
		_ = r.Close()
	})
	s := parseNoForkSpec(t, "SYSTEM:printf D >&4; printf E >&2,nofork,fdin=3,fdout=4,stderr")
	if err := runExecNoFork(context.Background(), peer, s, nil, ModeRDWR); err != nil {
		t.Fatal(err)
	}
	_ = outW.Close()
	os.Stderr = oldErr
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	stderrData, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(readStreamBytes(t, outR, 3*time.Second)); got != "DE" {
		t.Fatalf("relayed %q want DE (process stderr=%q)", got, stderrData)
	}
	if strings.Contains(string(stderrData), "E") {
		t.Fatalf("stderr option leaked E onto process stderr: %q", stderrData)
	}
}

func TestRunExecNoForkPipesSameFDInputWinsUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	script := filepath.Join(t.TempDir(), "same-fd.sh")
	body := "#!/bin/sh\nIFS= read -r line <&5\nprintf '%s' \"$line\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	peer, inW, _, _ := noForkPipePeer(t)
	if _, err := inW.Write([]byte("input-wins\n")); err != nil {
		t.Fatal(err)
	}
	if err := inW.Close(); err != nil {
		t.Fatal(err)
	}
	got := captureInheritedStdout(t, func() {
		s := parseNoForkSpec(t, "EXEC:"+script+",nofork,fdin=5,fdout=5")
		if err := runExecNoFork(context.Background(), peer, s, nil, ModeRDWR); err != nil {
			t.Fatal(err)
		}
	})
	if got != "input-wins" {
		t.Fatalf("inherited stdout=%q want input-wins", got)
	}
}

func TestRunExecNoForkSocketFDInFDOutUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fds[0]), "nofork-parent")
	child := os.NewFile(uintptr(fds[1]), "nofork-child")
	t.Cleanup(func() {
		_ = parent.Close()
		_ = child.Close()
	})
	peer := relay.FDStream{R: child, W: child, C: NopCloser{}}
	const payload = "socket-payload"
	done := make(chan error, 1)
	go func() {
		if _, err := parent.Write([]byte(payload)); err != nil {
			done <- err
			return
		}
		_ = parent.Close()
		done <- nil
	}()
	got := captureInheritedStdout(t, func() {
		s := parseNoForkSpec(t, "SYSTEM:cat <&3,nofork,fdin=3")
		if err := runExecNoFork(context.Background(), peer, s, nil, ModeWrite); err != nil {
			t.Fatal(err)
		}
	})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got != payload {
		t.Fatalf("inherited stdout %q want %q", got, payload)
	}
}

func TestRunExecNoForkFailedStartLeavesParentFDsUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	marker, err := os.CreateTemp(t.TempDir(), "parent-fd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = marker.Close() })
	const keep = "parent-marker"
	if _, err := marker.WriteString(keep); err != nil {
		t.Fatal(err)
	}
	peer := relay.FDStream{R: strings.NewReader(""), W: io.Discard, C: NopCloser{}}
	fdin := int(marker.Fd())
	s := parseNoForkSpec(t, fmt.Sprintf("EXEC:/bin/true,nofork,fdin=%d,fdout=4", fdin))
	err = runExecNoFork(context.Background(), peer, s, nil, ModeRDWR)
	if err == nil {
		t.Fatal("peer without a file descriptor must fail before Start")
	}
	if !strings.Contains(err.Error(), "no file descriptor") {
		t.Fatalf("error=%v want no file descriptor", err)
	}
	got := make([]byte, len(keep)+8)
	n, readErr := marker.ReadAt(got, 0)
	if readErr != nil && readErr != io.EOF {
		t.Fatal(readErr)
	}
	if string(got[:n]) != keep {
		t.Fatalf("parent fd %d remapped: %q err=%v", fdin, got[:n], err)
	}
}

func TestRunExecNoForkExecFailureLeavesParentFDsUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	marker, err := os.CreateTemp(t.TempDir(), "parent-fd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = marker.Close() })
	const keep = "parent-marker"
	if _, err := marker.WriteString(keep); err != nil {
		t.Fatal(err)
	}
	peer, _, _, _ := noForkPipePeer(t)
	fdin := int(marker.Fd())
	g := &Global{Log: logx.New()}
	s := parseNoForkSpec(t, fmt.Sprintf("EXEC:/no/such/socat-nofork-missing,nofork,fdin=%d,fdout=4", fdin))
	err = runExecNoFork(context.Background(), peer, s, g, ModeRDWR)
	if err != nil {
		t.Fatalf("missing binary: err=%v want ChildExitCode 1", err)
	}
	if g.ChildExitCode != 1 {
		t.Fatalf("missing binary: ChildExitCode=%d want 1 (classic execvp Exit(1))", g.ChildExitCode)
	}
	got := make([]byte, len(keep)+8)
	n, readErr := marker.ReadAt(got, 0)
	if readErr != nil && readErr != io.EOF {
		t.Fatal(readErr)
	}
	if string(got[:n]) != keep {
		t.Fatalf("parent fd %d remapped: %q", fdin, got[:n])
	}
}

func TestRunExecNoForkBareSHELLReadsStdinUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = pr
	t.Cleanup(func() {
		os.Stdin = old
		_ = pw.Close()
		_ = pr.Close()
	})
	if _, err := pw.Write([]byte("printf OK\nexit\n")); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	peer, _, _, _ := noForkPipePeer(t)
	got := captureInheritedStdout(t, func() {
		s := parseNoForkSpec(t, "SHELL,nofork,fdin=3,shell=/bin/sh")
		if err := runExecNoFork(context.Background(), peer, s, nil, ModeWrite); err != nil {
			t.Fatal(err)
		}
	})
	if got != "OK" {
		t.Fatalf("bare SHELL inherited stdout=%q want OK", got)
	}
}

func TestRunExecNoForkTrueWithCustomFDsUnix(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	peer, _, _, _ := noForkPipePeer(t)
	s := parseNoForkSpec(t, "EXEC:true,nofork,fdin=3,fdout=4")
	g := &Global{Log: logx.New()}
	if err := runExecNoFork(context.Background(), peer, s, g, ModeRDWR); err != nil {
		t.Fatal(err)
	}
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
	if err := runExecNoFork(context.Background(), peer, s, g, ModeRDWR); err != nil {
		t.Fatal(err)
	}
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
		if err := runExecNoFork(context.Background(), peer, s, nil, ModeRDWR); err != nil {
			t.Fatal(err)
		}
	}))
	if got != "x-argv0" {
		t.Fatalf("nofork dash argv0=%q want x-argv0", got)
	}
}
