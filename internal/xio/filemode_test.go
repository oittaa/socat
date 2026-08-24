package xio

import (
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
	for _, opt := range []string{"perm=xyz", "mode=xyz", "perm=abc"} {
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
}
