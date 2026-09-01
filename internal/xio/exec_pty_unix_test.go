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

func TestEXECPtyKeepsParentSessionWithoutSetsid(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not enabled")
	}
	parent, err := unix.Getsid(0)
	if err != nil {
		t.Fatal(err)
	}
	bin := buildSidCttyHelper(t)
	for _, opt := range []string{"pty", "pty,setsid=0", "pty,ctty=0"} {
		t.Run(opt, func(t *testing.T) {
			sid, ctty := parseSidCtty(t, readExecPtyStdout(t, "EXEC:"+bin+","+opt+",rawer,echo=0"))
			if sid != parent {
				t.Fatalf("child sid=%d parent=%d want same session", sid, parent)
			}
			if ctty {
				t.Fatal("pty without setsid must not become the controlling terminal")
			}
		})
	}
}

func TestEXECPtySetsidStartsNewSession(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not enabled")
	}
	parent, err := unix.Getsid(0)
	if err != nil {
		t.Fatal(err)
	}
	bin := buildSidCttyHelper(t)
	for _, opt := range []string{"pty,setsid", "pty,setsid=1", "pty,sid"} {
		t.Run(opt, func(t *testing.T) {
			sid, ctty := parseSidCtty(t, readExecPtyStdout(t, "EXEC:"+bin+","+opt+",rawer,echo=0"))
			if sid == parent {
				t.Fatalf("child sid=%d still parent session", sid)
			}
			if ctty {
				t.Fatal("setsid without ctty must not take the controlling terminal")
			}
		})
	}
}

func TestEXECPtyCttyDoesNotImplySetsid(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not enabled")
	}
	parent, err := unix.Getsid(0)
	if err != nil {
		t.Fatal(err)
	}
	bin := buildSidCttyHelper(t)
	sid, ctty := parseSidCtty(t, readExecPtyStdout(t, "EXEC:"+bin+",pty,ctty,rawer,echo=0"))
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
	sid, ctty := parseSidCtty(t, readExecPtyStdout(t, "EXEC:"+bin+",pty,setsid,ctty,rawer,echo=0"))
	if sid == parent {
		t.Fatal("setsid,ctty kept the parent session")
	}
	if !ctty {
		t.Fatal("setsid,ctty must take the controlling terminal")
	}
}

func TestEXECPtyLinkCreatesAndRemovesSymlink(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not enabled")
	}
	link := filepath.Join(t.TempDir(), "exec-pty")
	bin := buildSidCttyHelper(t)
	o := openEXECSpec(t, "EXEC:"+bin+",pty,rawer,echo=0,link="+link, ModeRDWR)
	st, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("link missing: %v", err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("link is not a symlink")
	}
	target, err := os.Readlink(link)
	if err != nil || target == "" {
		t.Fatalf("readlink: %v %q", err, target)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("link survived Close: %v", err)
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

func TestEXECPtyLinkDoesNotRemoveDirectory(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not enabled")
	}
	dir := filepath.Join(t.TempDir(), "emptydir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("EXEC:/bin/true,pty,link=" + dir)
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenSpec(context.Background(), spec, ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected link= directory to fail")
	}
	fi, statErr := os.Lstat(dir)
	if statErr != nil {
		t.Fatalf("directory was removed: %v", statErr)
	}
	if !fi.IsDir() {
		t.Fatalf("mode=%v want directory", fi.Mode())
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

func TestPTYLinkPreservesReplacement(t *testing.T) {
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

func TestEXECPtmxAndOpenptySelectPTY(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not enabled")
	}
	bin := buildIsattyHelper(t)
	if got := readExecPtyStdout(t, "EXEC:"+bin); got != "notty" {
		t.Fatalf("default transport got %q want notty", got)
	}
	for _, opt := range []string{"pty", "ptmx", "openpty"} {
		t.Run(opt, func(t *testing.T) {
			got := readExecPtyStdout(t, "EXEC:"+bin+","+opt+",rawer,echo=0")
			if got != "tty" {
				t.Fatalf("%s transport got %q want tty", opt, got)
			}
		})
	}
	for _, opt := range []string{"pty=0", "ptmx=0", "openpty=0"} {
		t.Run(opt, func(t *testing.T) {
			if got := readExecPtyStdout(t, "EXEC:"+bin+","+opt); got != "notty" {
				t.Fatalf("%s transport got %q want notty", opt, got)
			}
		})
	}
}

func TestEXECRejectsWaitSlaveAndPtyInterval(t *testing.T) {
	for _, specText := range []string{
		"EXEC:/bin/true,pty,wait-slave",
		"EXEC:/bin/true,pty,pty-wait-slave",
		"EXEC:/bin/true,pty,pty-interval=0.2",
		"SYSTEM:true,pty,wait-slave",
		"SYSTEM:true,pty-interval=1",
	} {
		t.Run(specText, func(t *testing.T) {
			spec, err := parse.ParseSpec(specText)
			if err != nil {
				t.Fatal(err)
			}
			o, err := OpenSpec(context.Background(), spec, ModeRDWR, nil)
			if err == nil {
				_ = o.Close()
				t.Fatal("expected wait-slave/pty-interval to be rejected")
			}
			if !strings.Contains(err.Error(), "not supported") {
				t.Fatalf("error=%v want not supported", err)
			}
		})
	}
}

func readExecPtyStdout(t *testing.T, spec string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
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
	var buf bytes.Buffer
	tmp := make([]byte, 64)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, err := o.Stream.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if strings.Contains(buf.String(), "\n") {
			break
		}
		if err != nil {
			break
		}
	}
	_ = o.Close()
	got := strings.TrimSpace(strings.ReplaceAll(buf.String(), "\r", ""))
	if got == "" {
		t.Fatalf("no child output from %s", spec)
	}
	return got
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
	body := "#include <fcntl.h>\n#include <stdio.h>\n#include <unistd.h>\nint main(void){ int tty=open(\"/dev/tty\",O_RDWR); printf(\"sid=%d ctty=%d\\n\", (int)getsid(0), tty>=0); if(tty>=0) close(tty); return 0; }\n"
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

func buildIsattyHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "isatty.c")
	body := "#include <stdio.h>\n#include <unistd.h>\nint main(void){ printf(\"%s\\n\", isatty(0)?\"tty\":\"notty\"); return 0; }\n"
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "isatty")
	out, err := exec.Command("gcc", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Skipf("gcc unavailable: %v (%s)", err, out)
	}
	return bin
}
