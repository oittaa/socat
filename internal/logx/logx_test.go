package logx

import (
	"bytes"
	"strings"
	"testing"
)

func TestWithShutupDemotesOnlyChildLogger(t *testing.T) {
	var output bytes.Buffer
	parent := New()
	parent.SetOutput(&output)
	child := parent.WithShutup(1)
	child.Errorf("child failure")
	parent.Errorf("parent failure")
	got := output.String()
	if !strings.Contains(got, " W child failure") {
		t.Fatalf("child error was not demoted: %q", got)
	}
	if !strings.Contains(got, " E parent failure") {
		t.Fatalf("parent logger was changed: %q", got)
	}
}

func TestCloneDoesNotShareVerbosity(t *testing.T) {
	var buf bytes.Buffer
	parent := New()
	parent.SetOutput(&buf)
	parent.SetLevel(Error)
	child := parent.Clone()
	child.SetLevel(Debug)
	parent.Debugf("parent-debug")
	child.Debugf("child-debug")
	got := buf.String()
	if strings.Contains(got, "parent-debug") {
		t.Fatalf("parent debug leaked: %q", got)
	}
	if !strings.Contains(got, "child-debug") {
		t.Fatalf("child debug missing: %q", got)
	}
	if parent.Level() != Error {
		t.Fatalf("parent level=%v", parent.Level())
	}
}
