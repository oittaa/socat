//go:build darwin

package xio

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDarwinEXECPtyDrainsOutputAfterChildExit(t *testing.T) {
	bin := buildIsattyHelper(t)
	for _, opt := range []string{"pty", "ptmx", "openpty"} {
		t.Run(opt, func(t *testing.T) {
			for i := 0; i < 10; i++ {
				o := openEXECSpec(t, "EXEC:"+bin+","+opt+",rawer,echo=0", ModeRDWR)
				waitExecPTYChild(t, o)
				got := strings.TrimSpace(strings.ReplaceAll(string(readStreamBytes(t, o.Stream, time.Second)), "\r", ""))
				if got != "tty" {
					t.Fatalf("iteration %d: output %q want tty", i, got)
				}
				if err := o.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestDarwinEXECPtySilentChildReachesEOF(t *testing.T) {
	o := openEXECSpec(t, "SYSTEM:true,pty,rawer,echo=0", ModeRDWR)
	waitExecPTYChild(t, o)
	if got := readStreamBytes(t, o.Stream, time.Second); len(got) != 0 {
		t.Fatalf("silent child output %q", got)
	}
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

func waitExecPTYChild(t *testing.T, o *Opened) {
	t.Helper()
	select {
	case <-o.childDone:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for EXEC PTY child")
	}
}
