package netopen

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnixBindCreatedUnlinkRemovesOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "created")
	if err := os.WriteFile(path, []byte("created"), 0o600); err != nil {
		t.Fatal(err)
	}
	rememberUnixBindCreated(path).unlink()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("created path survived unlink: %v", err)
	}
}
