package xio

import (
	"bytes"
	"testing"
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
		first, err := ParseSocatData(input)
		second, err2 := ParseSocatData(input)
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

func FuzzParseTimeval(f *testing.F) {
	for _, seed := range []string{"", "0", "1", "0.25", "250ms", "-1", "NaN", "+Inf", "1e100", "banana"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip("input exceeds 4096 bytes")
		}
		a := ParseTimeval(input)
		b := ParseTimeval(input)
		if a != b {
			t.Fatalf("ParseTimeval is not deterministic: %v vs %v", a, b)
		}
	})
}

func FuzzParsePositiveInt(f *testing.F) {
	for _, seed := range []string{"", "0", "1", "-1", "65535", "999999999999999999999", "1.5", "0x10"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip("input exceeds 4096 bytes")
		}
		n1, err1 := ParsePositiveInt(input)
		n2, err2 := ParsePositiveInt(input)
		if (err1 == nil) != (err2 == nil) || n1 != n2 {
			t.Fatalf("ParsePositiveInt is not deterministic: %d/%v vs %d/%v", n1, err1, n2, err2)
		}
	})
}
