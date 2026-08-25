package xio

import (
	"bytes"
	"io"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestParseEscapeByte(t *testing.T) {
	tests := []struct {
		value   string
		want    byte
		wantErr bool
	}{
		{value: "27", want: 27},
		{value: "027", want: 23},
		{value: "0x1b", want: 0x1b},
		{value: "0X1B", want: 0x1b},
		{value: "0xff", want: 0xff},
		{value: "x", want: 'x'},
		{value: "256", wantErr: true},
		{value: "0x100", wantErr: true},
		{value: "0x", wantErr: true},
		{value: "esc", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			got, err := parseEscapeByte(tc.value)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseEscapeByte(%q)=%d, want error", tc.value, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("parseEscapeByte(%q)=%d, %v; want %d", tc.value, got, err, tc.want)
			}
		})
	}
}

func TestApplyEscapeHexStopsAtEscapeByte(t *testing.T) {
	spec, err := parse.ParseSpec("STDIO,escape=0x1b")
	if err != nil {
		t.Fatal(err)
	}
	inner := relay.FDStream{
		R: bytes.NewReader([]byte("ab\x1bcd")),
		W: io.Discard,
		C: NopCloser{},
	}
	stream, err := ApplyEscape(spec, inner)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ab" {
		t.Fatalf("ReadAll=%q want %q (escape=0x1b must not parse as NUL)", got, "ab")
	}
}
