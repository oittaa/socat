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
