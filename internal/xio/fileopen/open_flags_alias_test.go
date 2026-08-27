package fileopen

import (
	"os"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestOpenFlagsClassicAliases(t *testing.T) {
	tests := []struct {
		name string
		spec string
		mode xio.Mode
		// access is os.O_RDONLY, os.O_WRONLY, or -1 to skip.
		access int
		bit    int
	}{
		{name: "o-rdonly", spec: "OPEN:x,o-rdonly", mode: xio.ModeWrite, access: os.O_RDONLY},
		{name: "o-wronly", spec: "OPEN:x,o-wronly", mode: xio.ModeRead, access: os.O_WRONLY},
		{name: "o-rdwr", spec: "OPEN:x,o-rdwr", mode: xio.ModeRead, access: os.O_RDWR},
		{name: "o_rdwr", spec: "OPEN:x,o_rdwr", mode: xio.ModeRead, access: os.O_RDWR},
		{name: "o-creat", spec: "OPEN:x,o-creat", mode: xio.ModeWrite, access: -1, bit: os.O_CREATE},
		{name: "o-create", spec: "OPEN:x,o-create", mode: xio.ModeWrite, access: -1, bit: os.O_CREATE},
		{name: "o-excl", spec: "OPEN:x,o-excl", mode: xio.ModeWrite, access: -1, bit: os.O_EXCL},
		{name: "o-trunc", spec: "OPEN:x,o-trunc", mode: xio.ModeWrite, access: -1, bit: os.O_TRUNC},
		{name: "last-wins-wronly", spec: "OPEN:x,o-rdonly,o-wronly", mode: xio.ModeRead, access: os.O_WRONLY},
		{name: "last-wins-rdonly", spec: "OPEN:x,o-wronly,o-rdonly", mode: xio.ModeWrite, access: os.O_RDONLY},
		{name: "disabled-rdonly-does-not-replace", spec: "OPEN:x,o-wronly,o-rdonly=0", mode: xio.ModeRead, access: os.O_WRONLY},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			flags, err := OpenFlags(spec, tc.mode)
			if err != nil {
				t.Fatal(err)
			}
			if tc.access == os.O_RDONLY {
				if flags&os.O_WRONLY != 0 || flags&os.O_RDWR != 0 {
					t.Fatalf("flags=%#x want read-only", flags)
				}
			}
			if tc.access == os.O_WRONLY {
				if flags&os.O_WRONLY == 0 {
					t.Fatalf("flags=%#x want write-only", flags)
				}
			}
			if tc.access == os.O_RDWR {
				if flags&os.O_RDWR != os.O_RDWR {
					t.Fatalf("flags=%#x want read-write", flags)
				}
			}
			if tc.bit != 0 && flags&tc.bit == 0 {
				t.Fatalf("flags=%#x missing %#x", flags, tc.bit)
			}
		})
	}
}

func TestOpenFlagsNdelayAlias(t *testing.T) {
	if oNonblock == 0 {
		t.Skip("O_NONBLOCK not used on this platform")
	}
	spec, err := parse.ParseSpec("OPEN:x,ndelay")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := OpenFlags(spec, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&oNonblock == 0 {
		t.Fatalf("flags=%#x missing O_NONBLOCK", flags)
	}
	off, err := parse.ParseSpec("OPEN:x,ndelay,nonblock=0")
	if err != nil {
		t.Fatal(err)
	}
	flags, err = OpenFlags(off, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&oNonblock != 0 {
		t.Fatalf("last-wins nonblock=0 left O_NONBLOCK set (flags=%#x)", flags)
	}
}
