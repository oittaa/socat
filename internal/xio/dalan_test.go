package xio

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseDalanWidthsAndSigns(t *testing.T) {
	t.Parallel()
	native := binary.NativeEndian

	must := func(s string) []byte {
		t.Helper()
		data, _, err := ParseDalan(s, 'i')
		if err != nil {
			t.Fatalf("ParseDalan(%q): %v", s, err)
		}
		return data
	}

	intBytes := func(n int32) []byte {
		b := make([]byte, sizeCInt)
		native.PutUint32(b, uint32(n))
		return b
	}
	shortBytes := func(n int16) []byte {
		b := make([]byte, sizeCShort)
		native.PutUint16(b, uint16(n))
		return b
	}
	longBytes := func(n int64) []byte {
		b := make([]byte, sizeCLong)
		if sizeCLong == 4 {
			native.PutUint32(b, uint32(n))
		} else {
			native.PutUint64(b, uint64(n))
		}
		return b
	}

	if got := must("i-1"); string(got) != string(intBytes(-1)) {
		t.Fatalf("i-1=%x want %x", got, intBytes(-1))
	}
	if got := must("I1"); string(got) != string(intBytes(1)) {
		t.Fatalf("I1=%x want %x", got, intBytes(1))
	}
	if got := must("s-2"); string(got) != string(shortBytes(-2)) {
		t.Fatalf("s-2=%x want %x", got, shortBytes(-2))
	}
	if got := must("S65535"); string(got) != string(shortBytes(-1)) {
		t.Fatalf("S65535=%x want %x", got, shortBytes(-1))
	}
	if got := must("b-1"); len(got) != 2 || got[0] != 0xff || got[1] != 0 {
		t.Fatalf("b-1=%x want ff00 (classic signed-byte fallthrough)", got)
	}
	if got := must("B255"); len(got) != 1 || got[0] != 0xff {
		t.Fatalf("B255=%x want ff", got)
	}
	if got := must("l1"); string(got) != string(longBytes(1)) {
		t.Fatalf("l1=%x want %x", got, longBytes(1))
	}
	if got := must("L2"); string(got) != string(longBytes(2)) {
		t.Fatalf("L2=%x want %x", got, longBytes(2))
	}
}

func TestParseDalanConcatenationAndDefaultType(t *testing.T) {
	t.Parallel()
	native := binary.NativeEndian

	data, single, err := ParseDalan("i1i2", 'i')
	if err != nil || single || len(data) != 8 {
		t.Fatalf("i1i2: data=%x single=%v err=%v", data, single, err)
	}
	if native.Uint32(data[:4]) != 1 || native.Uint32(data[4:]) != 2 {
		t.Fatalf("i1i2 payload=%x", data)
	}

	data, single, err = ParseDalan("i1 2", 'i')
	if err != nil || single || len(data) != 8 {
		t.Fatalf("i1 2: data=%x single=%v err=%v", data, single, err)
	}
	if native.Uint32(data[:4]) != 1 || native.Uint32(data[4:]) != 2 {
		t.Fatalf("default-type continuation payload=%x", data)
	}

	data, single, err = ParseDalan("512", 'i')
	if err != nil || !single || native.Uint32(data) != 512 {
		t.Fatalf("512: data=%x single=%v err=%v", data, single, err)
	}

	data, single, err = ParseDalan("i512", 'i')
	if err != nil || !single || native.Uint32(data) != 512 {
		t.Fatalf("i512: data=%x single=%v err=%v", data, single, err)
	}

	data, _, err = ParseDalan("s1 2", 'i')
	if err != nil || len(data) != 4 {
		t.Fatalf("s1 2: data=%x err=%v", data, err)
	}
	if native.Uint16(data[:2]) != 1 || native.Uint16(data[2:]) != 2 {
		t.Fatalf("short default continuation payload=%x", data)
	}

	// Classic's signed-byte case falls through to unsigned-byte. The second
	// conversion consumes a following untyped number when one is available.
	data, single, err = ParseDalan("b1 2", 'i')
	if err != nil || single || len(data) != 2 || data[0] != 1 || data[1] != 2 {
		t.Fatalf("b1 2: data=%x single=%v err=%v", data, single, err)
	}
}

func TestParseDalanStringsCharsHex(t *testing.T) {
	t.Parallel()
	data, single, err := ParseDalan(`"ab\n"`, 'i')
	if err != nil || single || string(data) != "ab\n" {
		t.Fatalf("string: data=%q single=%v err=%v", data, single, err)
	}
	data, _, err = ParseDalan(`'x'`, 'i')
	if err != nil || string(data) != "x" {
		t.Fatalf("char: data=%q err=%v", data, err)
	}
	data, _, err = ParseDalan(`'\n'`, 'i')
	if err != nil || len(data) != 1 || data[0] != '\n' {
		t.Fatalf("escaped char: data=%q err=%v", data, err)
	}
	data, _, err = ParseDalan("x0102", 'i')
	if err != nil || hex.EncodeToString(data) != "0102" {
		t.Fatalf("hex: data=%x err=%v", data, err)
	}
	data, _, err = ParseDalan(`"A"'B'x00i1`, 'i')
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 7 || data[0] != 'A' || data[1] != 'B' || data[2] != 0 {
		t.Fatalf("mixed typed elements: %x", data)
	}
	if binary.NativeEndian.Uint32(data[3:]) != 1 {
		t.Fatalf("mixed trailing int: %x", data)
	}
}

func TestParseDalanRejectsLeftoverAndEmptyNumeric(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"512junk", "not-a-dalan-path", "i", "x0", "'ab'", `"unterminated`} {
		if _, _, err := ParseDalan(s, 'i'); err == nil {
			t.Errorf("ParseDalan(%q) succeeded", s)
		} else if !strings.Contains(err.Error(), "syntax error") {
			t.Errorf("ParseDalan(%q): %v want syntax error", s, err)
		}
	}
}

func TestParseSockoptBinRejectsSocatDataPath(t *testing.T) {
	t.Parallel()
	if _, _, _, err := parseSockoptBin("not-a-dalan-path"); err == nil {
		t.Fatal("ASCII path fallback must not be used for setsockopt-bin")
	}
	if _, _, _, err := parseSockoptBin(""); err == nil {
		t.Fatal("empty dalan must fail")
	}
}
