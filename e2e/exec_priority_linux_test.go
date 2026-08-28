//go:build e2e && linux

package e2e_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEXECSOPriorityUnidirectionalCat(t *testing.T) {
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skip("/bin/cat not available")
	}
	bin := socatBin(t)
	const payload = "hello"

	t.Run("exec-to-stdout", func(t *testing.T) {
		// printf hello | socat -u EXEC:/bin/cat,so-priority=5 STDOUT
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "-t", "1", "-u", "EXEC:/bin/cat,so-priority=5", "STDOUT")
		cmd.Stdin = strings.NewReader(payload)
		var out, errb bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errb
		if err := cmd.Run(); err != nil {
			t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb.Bytes(), out.Bytes())
		}
		if got := out.String(); got != payload {
			t.Fatalf("got %q want %q", got, payload)
		}
	})

	t.Run("stdin-to-exec", func(t *testing.T) {
		// printf hello | socat -u STDIN EXEC:/bin/cat,so-priority=5
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "-t", "1", "-u", "STDIN", "EXEC:/bin/cat,so-priority=5")
		cmd.Stdin = strings.NewReader(payload)
		var out, errb bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errb
		if err := cmd.Run(); err != nil {
			t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb.Bytes(), out.Bytes())
		}
		if got := out.String(); got != payload {
			t.Fatalf("got %q want %q", got, payload)
		}
	})
}

func TestEXECSOPriorityFDInFDOutInheritStandardStreams(t *testing.T) {
	bin := socatBin(t)
	sink := filepath.Join(t.TempDir(), "relayed")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(
		ctx,
		bin,
		"-t", "1",
		"SYSTEM:printf O; printf D >&4,fdin=3,fdout=4,so-priority=5",
		"SYSTEM:cat >"+sink,
	)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb.Bytes(), out.Bytes())
	}
	if got := out.String(); got != "O" {
		t.Fatalf("inherited stdout got %q want %q", got, "O")
	}
	data, err := os.ReadFile(sink)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "D" {
		t.Fatalf("relayed fdout got %q want %q", got, "D")
	}
}

func TestEXECEndCloseSOPriorityApplies(t *testing.T) {
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skip("/bin/cat not available")
	}
	const payload = "hello"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, socatBin(t), "-t", "1", "-u", "EXEC:/bin/cat,end-close,so-priority=5", "STDOUT")
	cmd.Stdin = strings.NewReader(payload)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb.Bytes(), out.Bytes())
	}
	if got := out.String(); got != payload {
		t.Fatalf("got %q want %q", got, payload)
	}
}

func TestEXECPipesEndCloseSOPriorityLeftoverRejects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, socatBin(t), "-t", "1", "EXEC:/bin/true,pipes,end-close,so-priority=5", "STDOUT")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected leftover PASTSOCKET error, stdout=%q stderr=%s", out.Bytes(), errb.Bytes())
	}
	if !strings.Contains(errb.String(), `option "so-priority" not inquired`) {
		t.Fatalf("stderr=%q want option %q not inquired", errb.String(), "so-priority")
	}
}
