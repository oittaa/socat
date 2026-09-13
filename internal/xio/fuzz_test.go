package xio

import (
	"bytes"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
)

func FuzzParseSocatData(f *testing.F) {
	for _, seed := range []string{
		"", `"path\0"`, `\"path\0\"`, "x00ff", "x00FFx0a", "'c'", `'\n'`,
		`'ab'`, "x0", `hello\tworld`, `"unterminated`, `"a""b"`, "xgg",
		"X0102", "X0102X0304", "x0102X0304", "x00FF", `"X"`, `'X'`, "x0102x0304",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip("input exceeds 4096 bytes")
		}
		first, err := addrconfig.ParseSocatData(input)
		second, err2 := addrconfig.ParseSocatData(input)
		if (err == nil) != (err2 == nil) {
			t.Fatalf("ParseSocatData error is not deterministic: %v vs %v", err, err2)
		}
		if err != nil {
			return
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("ParseSocatData is not deterministic")
		}
	})
}

func FuzzParseDurationValue(f *testing.F) {
	for _, seed := range []string{"", "0", "1", "0.25", "250ms", "-1", "NaN", "+Inf", "1e100", "banana"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip("input exceeds 4096 bytes")
		}
		a, err1 := addrconfig.ParseDuration(input)
		b, err2 := addrconfig.ParseDuration(input)
		if (err1 == nil) != (err2 == nil) || a != b {
			t.Fatalf("ParseDuration is not deterministic: %v/%v vs %v/%v", a, err1, b, err2)
		}
	})
}
