//go:build unix

package xio

import (
	"context"
	"io"
	"os"
	"os/exec"
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

func TestNormalizeProcessFDClassicUShortRange(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  string
	}{
		{value: "9", want: "9"},
		{value: "10", want: "10"},
		{value: "0x10", want: "16"},
		{value: "017", want: "15"},
		{value: "65535", want: "65535"},
	} {
		got, err := normalizeProcessFD(tc.value, "fdin")
		if err != nil || got != tc.want {
			t.Fatalf("fdin=%s: got %q err=%v want %q", tc.value, got, err, tc.want)
		}
	}
	_, err := normalizeProcessFD("65536", "fdin")
	if err == nil || !strings.Contains(err.Error(), "unsigned-short range") {
		t.Fatalf("fdin=65536 error=%v", err)
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

func TestRebuildWithFDHelperKeepsBareShellArgv(t *testing.T) {
	s, err := parse.ParseSpec("SHELL,shell=/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := shellCommand(context.Background(), s, "", false)
	wrapped, err := rebuildWithFDHelper(context.Background(), cmd, "3", "", "3", "", false)
	if err != nil {
		t.Fatal(err)
	}
	idx := -1
	for i, a := range wrapped.Args {
		if a == execFDHelperMarker {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("missing helper marker in %q", wrapped.Args)
	}
	if len(wrapped.Args) != idx+8 {
		t.Fatalf("args=%q want helper + path + argv0 only (no -c)", wrapped.Args)
	}
	if wrapped.Args[idx+7] != "sh" {
		t.Fatalf("argv0=%q want sh", wrapped.Args[idx+7])
	}
	for _, a := range wrapped.Args {
		if a == "-c" {
			t.Fatalf("bare SHELL grew -c in %q", wrapped.Args)
		}
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
