//go:build unix

package xio

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

func openProcess(t *testing.T, spec string, mode Mode) *Opened {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	g := &Global{BlockSize: 8192, Log: logx.New(), Linger: 50 * time.Millisecond}
	var o *Opened
	switch strings.ToUpper(s.Type) {
	case "EXEC":
		o, err = openEXEC(context.Background(), s, mode, g)
	case "SYSTEM":
		o, err = openSYSTEM(context.Background(), s, mode, g)
	case "SHELL":
		o, err = openSHELL(context.Background(), s, mode, g)
	default:
		t.Fatalf("unexpected type %s", s.Type)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func readExactProcess(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(r, buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		return buf
	case <-time.After(3 * time.Second):
		t.Fatal("timed out reading")
		return nil
	}
}

func readAllProcess(t *testing.T, r io.Reader) []byte {
	t.Helper()
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
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.b
	case <-time.After(3 * time.Second):
		t.Fatal("timed out reading to EOF")
		return nil
	}
}

func TestEXECPrintsStdout(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	o := openProcess(t, "EXEC:/bin/echo socat-exec-ok", ModeRead)
	got := strings.TrimSpace(string(readAllProcess(t, o.Stream)))
	if got != "socat-exec-ok" {
		t.Fatalf("EXEC got %q", got)
	}
}

func TestSYSTEMRunsShellCommand(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("SYSTEM not enabled")
	}
	dir := t.TempDir()
	o := openProcess(t, "SYSTEM:pwd,chdir="+dir, ModeRead)
	got := strings.TrimSpace(string(readAllProcess(t, o.Stream)))
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

func TestSHELLHonorsShellOption(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("SHELL not enabled")
	}
	o := openProcess(t, "SHELL:printf socat-shell-ok,shell=/bin/sh", ModeRead)
	if got := string(readAllProcess(t, o.Stream)); got != "socat-shell-ok" {
		t.Fatalf("SHELL got %q", got)
	}
}

func TestSYSTEMSocketpairRoundtrip(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("SYSTEM not enabled")
	}
	o := openProcess(t, "SYSTEM:dd bs=1 count=5 2>/dev/null", ModeRDWR)
	const payload = "abcde"
	if _, err := io.WriteString(o.Stream, payload); err != nil {
		t.Fatal(err)
	}
	if got := string(readExactProcess(t, o.Stream, len(payload))); got != payload {
		t.Fatalf("SYSTEM socketpair got %q", got)
	}
}

func TestEXECPtyRoundtrip(t *testing.T) {
	if !FeatureEXEC || !FeaturePTY {
		t.Skip("EXEC/PTY not enabled")
	}
	if _, err := exec.LookPath("dd"); err != nil {
		t.Skip("dd not on PATH")
	}
	o := openProcess(t, "EXEC:dd bs=1 count=5,pty,setsid,stderr,rawer,echo=0", ModeRDWR)
	const payload = "abcde"
	if _, err := io.WriteString(o.Stream, payload); err != nil {
		t.Fatal(err)
	}
	got := readExactProcess(t, o.Stream, len(payload))
	if string(got) != payload {
		t.Fatalf("EXEC,pty got %q want %q", got, payload)
	}
}

func TestEXECfdinFdout(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	o := openProcess(t, "SYSTEM:dd bs=1 count=5 <&3 >&4 2>/dev/null,fdin=3,fdout=4", ModeRDWR)
	const payload = "fghij"
	if _, err := io.WriteString(o.Stream, payload); err != nil {
		t.Fatal(err)
	}
	if got := string(readExactProcess(t, o.Stream, len(payload))); got != payload {
		t.Fatalf("fdin/fdout got %q", got)
	}
}

func TestEXECfdinJoinsArgv(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	if _, err := exec.LookPath("dd"); err != nil {
		t.Skip("dd not on PATH")
	}
	o := openProcess(t, "EXEC:dd bs=1 count=5,fdin=3,fdout=4", ModeRDWR)
	const payload = "klmno"
	if _, err := io.WriteString(o.Stream, payload); err != nil {
		t.Fatal(err)
	}
	if got := string(readExactProcess(t, o.Stream, len(payload))); got != payload {
		t.Fatalf("EXEC fdin argv got %q", got)
	}
}
