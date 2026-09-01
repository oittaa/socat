package xio

import (
	"context"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestOpenSpecRejectsOpenpty(t *testing.T) {
	for _, specText := range []string{
		"EXEC:/bin/true,openpty",
		"SYSTEM:true,openpty",
		"SHELL:true,openpty",
		"PTY,openpty",
	} {
		t.Run(specText, func(t *testing.T) {
			spec, err := parse.ParseSpec(specText)
			if err != nil {
				t.Fatal(err)
			}
			o, err := OpenSpec(context.Background(), spec, ModeRDWR, nil)
			if err == nil {
				_ = o.Close()
				t.Fatal("expected openpty to be rejected")
			}
			if !strings.Contains(err.Error(), "not supported") {
				t.Fatalf("error=%v want not supported", err)
			}
		})
	}
}

func TestRejectUnsupportedOpenpty(t *testing.T) {
	spec, err := parse.ParseSpec("EXEC:/bin/true,openpty")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectUnsupportedOpenpty(spec)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("error=%v", err)
	}
	ok, err := parse.ParseSpec("EXEC:/bin/true,pty")
	if err != nil {
		t.Fatal(err)
	}
	if err := RejectUnsupportedOpenpty(ok); err != nil {
		t.Fatal(err)
	}
}
