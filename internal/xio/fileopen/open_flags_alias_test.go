package fileopen

import (
	"os"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestOpenFlagsZeroAfterAlias(t *testing.T) {
	spec, err := parse.ParseSpec("OPEN:x,o-rdonly,rdonly=0,o-wronly")
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: "OPEN"})
	if err != nil {
		t.Fatal(err)
	}
	flags, err := ConfiguredOpenFlags(config.File, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&os.O_WRONLY == 0 {
		t.Fatalf("flags=%#x want write-only after rdonly=0,o-wronly", flags)
	}
}
