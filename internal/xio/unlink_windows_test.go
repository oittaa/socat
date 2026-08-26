//go:build windows

package xio

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestUnlinkRemovesReadOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := Unlink(path); err != nil {
		t.Fatalf("Unlink read-only file: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("read-only file survived Unlink: %v", err)
	}
}

func TestUnlinkRefusesEmptyDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "emptydir")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Unlink(path); err == nil {
		t.Fatal("Unlink removed an empty directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("empty directory was replaced; mode=%v", info.Mode())
	}
}

func TestUnlinkRemovesDirectoryJunction(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	junction := filepath.Join(dir, "junction")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(target, "marker")
	if err := os.WriteFile(marker, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Skipf("cannot create directory junction: %v: %s", err, out)
	}

	if err := Unlink(junction); err != nil {
		t.Fatalf("Unlink directory junction: %v", err)
	}
	if _, err := os.Lstat(junction); !os.IsNotExist(err) {
		t.Fatalf("directory junction survived Unlink: %v", err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "target" {
		t.Fatalf("junction target was affected: content=%q err=%v", got, err)
	}
}
