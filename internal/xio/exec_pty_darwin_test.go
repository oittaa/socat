//go:build darwin

package xio

import (
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

func waitExecPTYChild(t *testing.T, o *Opened) {
	t.Helper()
	select {
	case <-o.childDone:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for EXEC PTY child")
	}
}
