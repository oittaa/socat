//go:build unix

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
		{name: "pty", spec: "SYSTEM:printf O; printf D >&4,pty,fdin=3,fdout=4,raw,echo=0", skip: func() bool { return !FeaturePTY }},
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
