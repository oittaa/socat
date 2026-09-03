//go:build linux || darwin

package xio

import (
	"bytes"
	"testing"
)

func FuzzParseHexOpt(f *testing.F) {
	for _, seed := range []string{"", "00", "ff", "x00ff", "0x0a", "gg", "0"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip("input exceeds 4096 bytes")
		}
		a, err1 := ParseHexOpt(input)
		b, err2 := ParseHexOpt(input)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("ParseHexOpt error is not deterministic: %v vs %v", err1, err2)
		}
		if err1 != nil {
			return
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("ParseHexOpt is not deterministic")
		}
	})
}
