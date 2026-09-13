package xio

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenSniffFilesClosesLeftWhenRightFails(t *testing.T) {
	dir := t.TempDir()
	left := filepath.ToSlash(filepath.Join(dir, "left.log"))
	notDir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	right := filepath.ToSlash(filepath.Join(notDir, "right.log"))
	g := NewSession(Options{RawLeftPath: left, RawRightPath: right}, nil)
	if err := openSniffFiles(g); err == nil {
		t.Fatal("expected -R open to fail")
	}
	if g.Sniff.RawLeft != nil || g.Sniff.RawRight != nil {
		t.Fatal("partial sniff open must close the first descriptor")
	}
}

func TestOpenSniffFilesChildDoesNotCloseParentOrSibling(t *testing.T) {
	path := filepath.ToSlash(filepath.Join(t.TempDir(), "shared.log"))
	parent := NewSession(Options{RawLeftPath: path}, nil)
	if err := openSniffFiles(parent); err != nil {
		t.Fatal(err)
	}
	defer parent.Sniff.closeFiles()
	child, sibling := parent.ForkSession(), parent.ForkSession()
	if err := openSniffFiles(child); err != nil {
		t.Fatal(err)
	}
	defer child.Sniff.closeFiles()
	if err := openSniffFiles(sibling); err != nil {
		t.Fatal(err)
	}
	defer sibling.Sniff.closeFiles()
	child.Sniff.closeFiles()
	if _, err := parent.Sniff.RawLeft.WriteString("parent\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := sibling.Sniff.RawLeft.WriteString("sibling\n"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "parent\nsibling\n" {
		t.Fatalf("sniff=%q error=%v", data, err)
	}
}
