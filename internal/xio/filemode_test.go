package xio

import (
	"os"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseFileModeDefaultAndExplicit(t *testing.T) {
	def := DefaultCreateMode
	if def != 0o666 {
		t.Fatalf("DefaultCreateMode=%#o want 0666", def)
	}
	plain, err := parse.ParseSpec("CREATE:file")
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseFileMode(plain, def)
	if err != nil {
		t.Fatal(err)
	}
	if m != def {
		t.Fatalf("mode=%#o want %#o", m, def)
	}

	explicit, err := parse.ParseSpec("CREATE:file,perm=600")
	if err != nil {
		t.Fatal(err)
	}
	m, err = ParseFileMode(explicit, def)
	if err != nil {
		t.Fatal(err)
	}
	if m != 0o600 {
		t.Fatalf("perm=600 mode=%#o", m)
	}
}

func TestParseFileModeRejectsInvalidOctal(t *testing.T) {
	for _, opt := range []string{
		"perm=xyz",
		"mode=xyz",
		"perm=abc",
		"perm=644junk",
		"perm=10000",
		"mode=8",
	} {
		spec, err := parse.ParseSpec("CREATE:file," + opt)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ParseFileMode(spec, DefaultCreateMode)
		if err == nil {
			t.Fatalf("%s: expected error", opt)
		}
		if !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("%s: error %v", opt, err)
		}
	}

	ok, err := parse.ParseSpec("CREATE:file,perm=7777")
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseFileMode(ok, DefaultCreateMode)
	if err != nil {
		t.Fatal(err)
	}
	if m != UnixModeToFileMode(0o7777) {
		t.Fatalf("perm=7777 mode=%#o want %#o", m, UnixModeToFileMode(0o7777))
	}
}

func TestUnixModePreservesSetuidBits(t *testing.T) {
	got := UnixModeToFileMode(0o4755)
	if got&os.ModeSetuid == 0 || got.Perm() != 0o755 {
		t.Fatalf("04755 → %#o perm=%#o setuid=%v", got, got.Perm(), got&os.ModeSetuid != 0)
	}
	if FileModeToUnix(got) != 0o4755 {
		t.Fatalf("round-trip %#o", FileModeToUnix(got))
	}
}

func TestParseFileModeLastWinsAcrossPermAndMode(t *testing.T) {
	permThenMode, err := parse.ParseSpec("CREATE:file,perm=600,mode=644")
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseFileMode(permThenMode, DefaultCreateMode)
	if err != nil {
		t.Fatal(err)
	}
	if m != 0o644 {
		t.Fatalf("perm=600,mode=644 got %#o want 0644", m)
	}

	modeThenPerm, err := parse.ParseSpec("CREATE:file,mode=644,perm=600")
	if err != nil {
		t.Fatal(err)
	}
	m, err = ParseFileMode(modeThenPerm, DefaultCreateMode)
	if err != nil {
		t.Fatal(err)
	}
	if m != 0o600 {
		t.Fatalf("mode=644,perm=600 got %#o want 0600", m)
	}
}
