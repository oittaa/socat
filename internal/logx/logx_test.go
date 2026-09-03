package logx

import (
	"bytes"
	"strings"
	"sync"
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

func TestConcurrentLogConfigClone(t *testing.T) {
	var buf bytes.Buffer
	parent := New()
	parent.SetOutput(&buf)
	parent.SetLevel(Warning)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				parent.Warningf("w")
				parent.Infof("i")
				parent.Increase()
				parent.SetLevel(Warning)
				c := parent.Clone()
				c.SetLevel(Debug)
				c.Debugf("d")
				s := parent.WithShutup(1)
				s.Errorf("e")
			}
		}()
	}
	wg.Wait()
}
