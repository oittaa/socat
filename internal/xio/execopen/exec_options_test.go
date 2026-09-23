//go:build linux || darwin

package execopen

import (
	"context"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
)

func TestStreamRWFilesFindsNestedDualFiles(t *testing.T) {
	stream := relay.FDStream{
		R: relay.FDStream{R: os.Stdin, W: io.Discard, C: xio.NopCloser{}},
		W: relay.FDStream{R: xio.EOFReader{}, W: os.Stdout, C: xio.NopCloser{}},
		C: xio.NopCloser{},
	}
	r, w, single, err := streamRWFiles(stream)
	if err != nil {
		t.Fatal(err)
	}
	if r != os.Stdin || w != os.Stdout || single != nil {
		t.Fatalf("r=%v w=%v single=%v", r, w, single)
	}
}

func TestShellCommandHonorsShellOption(t *testing.T) {
	s, err := parse.ParseSpec("SHELL:echo hi,shell=/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := xio.PrepareSpec(s)
	if err != nil {
		t.Fatal(err)
	}
	cmd := configuredShellCommand(context.Background(), prepared.Config.Process, xio.Options{Shell: "/bin/false"})
	if cmd.Path != "/bin/sh" {
		t.Fatalf("path=%q want /bin/sh", cmd.Path)
	}
	if len(cmd.Args) != 3 || cmd.Args[0] != "sh" || cmd.Args[1] != "-c" || cmd.Args[2] != "echo hi" {
		t.Fatalf("args=%q", cmd.Args)
	}
}

func TestShellCommandUsesProcessDefaultForInteractive(t *testing.T) {
	s, err := parse.ParseSpec("SHELL")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := xio.PrepareSpec(s)
	if err != nil {
		t.Fatal(err)
	}
	cmd := configuredShellCommand(context.Background(), prepared.Config.Process, xio.Options{Shell: "/bin/sh"})
	if len(cmd.Args) != 1 || cmd.Args[0] != "sh" {
		t.Fatalf("interactive args=%q want [sh]", cmd.Args)
	}
}

func TestEmptyQuotedSYSTEMCommandOpens(t *testing.T) {
	s, err := parse.ParseSpec(`SYSTEM:""`)
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenSpec(context.Background(), s, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
}

func TestRebuildWithFDHelperPreservesDashArgv0(t *testing.T) {
	cmd := exec.Command("/bin/true")
	cmd.Args[0] = "-true"
	wrapped, err := rebuildWithFDHelper(context.Background(), cmd, "3", "4", "3", "4", false)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped.Args[len(wrapped.Args)-1] != "-true" {
		t.Fatalf("helper target argv0=%q want -true in %q", wrapped.Args[len(wrapped.Args)-1], wrapped.Args)
	}
}
