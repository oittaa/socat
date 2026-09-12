package xio

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenSniffFilesClosesLeftWhenRightFails(t *testing.T) {
	dir := t.TempDir()
	left := filepath.Join(dir, "left.log")
	// A missing parent directory is not a portable -R failure: Windows
	// creates that path. A regular file as the parent fails on linux,
	// darwin, and windows.
	notDir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	right := filepath.Join(notDir, "right.log")
	g := NewSession(Options{RawLeftPath: left, RawRightPath: right}, nil)
	if err := openSniffFiles(g); err == nil {
		t.Fatal("expected -R open to fail")
	}
	if g.Sniff.RawLeft != nil || g.Sniff.RawRight != nil {
		t.Fatal("partial sniff open must close the first descriptor")
	}
	f, err := os.OpenFile(left, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.WriteString("after-fail\n"); err != nil {
		t.Fatal(err)
	}
}

func TestOpenSniffFilesChildDoesNotCloseParentOrSibling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.log")
	parent := NewSession(Options{RawLeftPath: path}, nil)
	if err := openSniffFiles(parent); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parent.Sniff.closeFiles)

	child := parent.ForkSession()
	if err := openSniffFiles(child); err != nil {
		t.Fatal(err)
	}
	if child.Sniff.RawLeft == nil || child.Sniff.RawLeft == parent.Sniff.RawLeft {
		t.Fatal("child must own a distinct sniff file")
	}

	sibling := parent.ForkSession()
	if err := openSniffFiles(sibling); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sibling.Sniff.closeFiles)
	if sibling.Sniff.RawLeft == parent.Sniff.RawLeft || sibling.Sniff.RawLeft == child.Sniff.RawLeft {
		t.Fatal("sibling must own a distinct sniff file")
	}

	child.Sniff.closeFiles()
	if child.Sniff.RawLeft != nil {
		t.Fatal("child close must clear its file")
	}
	if _, err := parent.Sniff.RawLeft.WriteString("parent\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := sibling.Sniff.RawLeft.WriteString("sibling\n"); err != nil {
		t.Fatal(err)
	}
}
