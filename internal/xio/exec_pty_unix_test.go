//go:build linux || darwin

package xio

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestEXECPtyCttyDoesNotImplySetsid(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not enabled")
	}
	parent, err := unix.Getsid(0)
	if err != nil {
		t.Fatal(err)
	}
	bin := buildSidCttyHelper(t)
	sid, ctty := parseSidCtty(t, readExecPtySessionProbe(t, bin, "EXEC:"+bin+",pty,ctty,rawer,echo=0"))
	if sid != parent {
		t.Fatalf("ctty without setsid changed sid %d → %d", parent, sid)
	}
	if ctty {
		t.Fatal("ctty without setsid must not take the controlling terminal")
	}
}

func TestEXECPtySetsidCttyTakesControllingTerminal(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not enabled")
	}
	parent, err := unix.Getsid(0)
	if err != nil {
		t.Fatal(err)
	}
	bin := buildSidCttyHelper(t)
	sid, ctty := parseSidCtty(t, readExecPtySessionProbe(t, bin, "EXEC:"+bin+",pty,setsid,ctty,rawer,echo=0"))
	if sid == parent {
		t.Fatal("setsid,ctty kept the parent session")
	}
	if !ctty {
		t.Fatal("setsid,ctty must take the controlling terminal")
	}
}

func TestEXECPtyLinkPreservesReplacement(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not enabled")
	}
	link := filepath.Join(t.TempDir(), "exec-pty")
	bin := buildSidCttyHelper(t)
	o := openEXECSpec(t, "EXEC:"+bin+",pty,rawer,echo=0,link="+link, ModeRDWR)
	replaceAtPath(t, link, []byte("replacement"), 0o600)
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(link)
	if err != nil {
		t.Fatalf("replacement path was removed: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("contents=%q", got)
	}
}

func TestEXECPtyLinkInvalidPathFails(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not enabled")
	}
	spec, err := parse.ParseSpec("EXEC:/bin/true,pty,link=/no/such/exec-pty-dir/link")
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenSpec(context.Background(), spec, ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected invalid link= path to fail")
	}
	if !strings.Contains(err.Error(), "link") {
		t.Fatalf("error=%v want link", err)
	}
}

func TestPTYLinkStillCreatesSymlink(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not enabled")
	}
	link := filepath.Join(t.TempDir(), "pty-addr")
	ch, err := parse.ParseChannel("PTY,echo=0,link=" + link)
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenChannel(context.Background(), ch, ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("PTY link missing: %v", err)
	}
}

// readExecPtySessionProbe uses a sidecar file for the session/ctty result.
// Those tests exercise child process attributes, not PTY data transfer; using
// PTY stdout made them susceptible to a Darwin master/slave startup race.
func readExecPtySessionProbe(t *testing.T, bin, spec string) string {
	t.Helper()
	resultPath := bin + ".result"
	if err := os.Remove(resultPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenChannel(ctx, ch, ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		data, readErr := os.ReadFile(resultPath)
		if readErr == nil && bytes.Contains(data, []byte("\n")) {
			return strings.TrimSpace(string(data))
		}
		if readErr != nil && !os.IsNotExist(readErr) {
			t.Fatal(readErr)
		}
		select {
		case <-ticker.C:
		case <-o.childDone:
			data, _ = os.ReadFile(resultPath)
			t.Fatalf("child exited before writing session probe for %s: %q", spec, data)
		case <-timer.C:
			t.Fatalf("timed out waiting for session probe from %s", spec)
		case <-ctx.Done():
			t.Fatalf("session probe from %s: %v", spec, ctx.Err())
		}
	}
}

func parseSidCtty(t *testing.T, got string) (sid int, ctty bool) {
	t.Helper()
	fields := strings.Fields(got)
	if len(fields) != 2 || !strings.HasPrefix(fields[0], "sid=") || !strings.HasPrefix(fields[1], "ctty=") {
		t.Fatalf("child output %q want sid=N ctty=0|1", got)
	}
	var err error
	sid, err = strconv.Atoi(strings.TrimPrefix(fields[0], "sid="))
	if err != nil {
		t.Fatal(err)
	}
	switch strings.TrimPrefix(fields[1], "ctty=") {
	case "1":
		ctty = true
	case "0":
	default:
		t.Fatalf("ctty field %q", fields[1])
	}
	return sid, ctty
}

func buildSidCttyHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "sidtty.c")
	body := "#include <fcntl.h>\n#include <stdio.h>\n#include <unistd.h>\nint main(int argc,char **argv){ char path[4096]; int tty=open(\"/dev/tty\",O_RDWR|O_NONBLOCK); char ch; if(snprintf(path,sizeof(path),\"%s.result\",argv[0])<0) return 2; FILE *out=fopen(path,\"w\"); if(!out) return 3; fprintf(out,\"sid=%d ctty=%d\\n\",(int)getsid(0),tty>=0); if(fclose(out)!=0) return 4; (void)argc; (void)read(STDIN_FILENO,&ch,1); if(tty>=0) close(tty); return 0; }\n"
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "sidtty")
	out, err := exec.Command("gcc", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Skipf("gcc unavailable: %v (%s)", err, out)
	}
	return bin
}
