//go:build linux || darwin

package execopen

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestOpenEXECParentSignalAssignmentRejected(t *testing.T) {
	spec, err := parse.ParseSpec("EXEC:true,sighup=0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenSpec(context.Background(), spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil || !strings.Contains(err.Error(), "no value permitted") {
		t.Fatalf("error=%v want no value permitted", err)
	}
}

func TestChildWaitExitCodeNormal(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 7")
	err := cmd.Run()
	code, ok := childWaitExitCode(err)
	if !ok || code != 7 {
		t.Fatalf("childWaitExitCode=%d ok=%v err=%v want 7", code, ok, err)
	}
	code, ok = childWaitExitCode(nil)
	if !ok || code != 0 {
		t.Fatalf("nil wait code=%d ok=%v want 0", code, ok)
	}
}
