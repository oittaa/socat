//go:build unix

package xio

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestValidateProcessFDOptions(t *testing.T) {
	tests := []struct {
		name        string
		mode        Mode
		fdin, fdout string
		wantErr     string
	}{
		{name: "duplex", mode: ModeRDWR, fdin: "3", fdout: "4"},
		{name: "write-fdin", mode: ModeWrite, fdin: "3"},
		{name: "read-fdout", mode: ModeRead, fdout: "4"},
		{name: "write-fdout", mode: ModeWrite, fdout: "4", wantErr: "fdout"},
		{name: "read-fdin", mode: ModeRead, fdin: "3", wantErr: "fdin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProcessFDOptions(tt.mode, tt.fdin, tt.fdout)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error=%v want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeProcessFDDashRange(t *testing.T) {
	got, err := normalizeProcessFD("9", "fdin")
	if err != nil || got != "9" {
		t.Fatalf("fdin=9: got %q err=%v", got, err)
	}
	_, err = normalizeProcessFD("10", "fdin")
	if err == nil || !strings.Contains(err.Error(), "cannot be applied through /bin/sh redirection") {
		t.Fatalf("fdin=10 error=%v", err)
	}
	_, err = normalizeProcessFD("10", "fdout")
	if err == nil || !strings.Contains(err.Error(), "fdout") {
		t.Fatalf("fdout=10 error=%v", err)
	}
}

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
	cmd := shellCommand(context.Background(), s, "echo hi", true)
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
	cmd := shellCommand(context.Background(), s, "", false)
	if len(cmd.Args) != 1 || cmd.Args[0] != "sh" {
		t.Fatalf("interactive args=%q want [sh]", cmd.Args)
	}
}

func TestRunExecNoForkSHELLUsesShellOption(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	script := filepath.Join(dir, "myshell")
	body := "#!/bin/sh\nprintf ran >'" + marker + "'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := parse.ParseSpec("SHELL:true,shell=" + script + ",nofork")
	if err != nil {
		t.Fatal(err)
	}
	peer := relay.FDStream{R: os.Stdin, W: os.Stdout, C: NopCloser{}}
	if err := runExecNoFork(context.Background(), peer, s, nil, ModeRDWR); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("custom shell was not executed: %v", err)
	}
	if string(got) != "ran" {
		t.Fatalf("marker=%q", got)
	}
}
