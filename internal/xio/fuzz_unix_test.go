//go:build linux || darwin

package xio

import (
	"bytes"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
)

func FuzzParseHexOpt(f *testing.F) {
	for _, seed := range []string{"", "00", "ff", "x00ff", "0x0a", "gg", "0"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip("input exceeds 4096 bytes")
		}
		a, aInt, err1 := addrconfig.ParseDalan(input, 'i')
		b, bInt, err2 := addrconfig.ParseDalan(input, 'i')
		if (err1 == nil) != (err2 == nil) || aInt != bInt {
			t.Fatalf("ParseDalan is not deterministic: %v/%v vs %v/%v", err1, aInt, err2, bInt)
		}
		if err1 != nil {
			return
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("ParseDalan is not deterministic")
		}
	})
}
