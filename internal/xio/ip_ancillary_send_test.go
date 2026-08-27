package xio

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseHexOptUsesClassicDalan(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []byte
	}{
		{name: "hex", value: "x0102", want: []byte{0x01, 0x02}},
		{name: "string", value: `"AB"`, want: []byte("AB")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHexOpt(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(tt.want) {
				t.Fatalf("ParseHexOpt(%q)=%x want %x", tt.value, got, tt.want)
			}
		})
	}

	got, err := ParseHexOpt("1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != sizeCInt || binary.NativeEndian.Uint32(got) != 1 {
		t.Fatalf("ParseHexOpt(1)=%x want one native C int containing 1", got)
	}
}

func TestParseHexOptRejectsMalformedAndOversizedValues(t *testing.T) {
	for _, value := range []string{"x0", "x" + strings.Repeat("00", maxIPOptions+1)} {
		if _, err := ParseHexOpt(value); err == nil {
			t.Fatalf("ParseHexOpt(%q) unexpectedly succeeded", value)
		}
	}
}
