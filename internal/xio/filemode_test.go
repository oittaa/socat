package xio

import (
	"os"
	"testing"
)

func TestUnixModePreservesSetuidBits(t *testing.T) {
	got := UnixModeToFileMode(0o4755)
	if got&os.ModeSetuid == 0 || got.Perm() != 0o755 {
		t.Fatalf("04755 → %#o perm=%#o setuid=%v", got, got.Perm(), got&os.ModeSetuid != 0)
	}
	if FileModeToUnix(got) != 0o4755 {
		t.Fatalf("round-trip %#o", FileModeToUnix(got))
	}
}
