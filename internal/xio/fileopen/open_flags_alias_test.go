package fileopen

import (
	"os"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestOpenFlagsZeroAfterAlias(t *testing.T) {
	spec, err := parse.ParseSpec("OPEN:x,o-rdonly,rdonly=0,o-wronly")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := OpenFlags(spec, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&os.O_WRONLY == 0 {
		t.Fatalf("flags=%#x want write-only after rdonly=0,o-wronly", flags)
	}
}
