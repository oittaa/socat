//go:build linux || darwin

package xio

import (
	"context"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestStreamRWFilesFindsNestedDualFiles(t *testing.T) {
	stream := relay.FDStream{
		R: relay.FDStream{R: os.Stdin, W: io.Discard, C: NopCloser{}},
		W: relay.FDStream{R: EOFReader{}, W: os.Stdout, C: NopCloser{}},
		C: NopCloser{},
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
	prepared, err := PrepareSpec(s)
	if err != nil {
		t.Fatal(err)
	}
	cmd := configuredShellCommand(context.Background(), prepared.Config.Process)
	if cmd.Path != "/bin/sh" {
		t.Fatalf("path=%q want /bin/sh", cmd.Path)
	}
	if len(cmd.Args) != 3 || cmd.Args[0] != "sh" || cmd.Args[1] != "-c" || cmd.Args[2] != "echo hi" {
		t.Fatalf("args=%q", cmd.Args)
	}
}

func TestShellCommandEmptyRunsInteractive(t *testing.T) {
	s, err := parse.ParseSpec("SHELL,shell=/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareSpec(s)
	if err != nil {
		t.Fatal(err)
	}
	cmd := configuredShellCommand(context.Background(), prepared.Config.Process)
	if len(cmd.Args) != 1 || cmd.Args[0] != "sh" {
		t.Fatalf("interactive args=%q want [sh]", cmd.Args)
	}
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
