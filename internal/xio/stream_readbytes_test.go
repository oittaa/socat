package xio

import (
	"io"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestApplyReadBytesClassicSizeT(t *testing.T) {
	const payload = "0123456789abcdef"
	tests := []struct {
		name    string
		opt     string
		want    string
		wantErr bool
	}{
		{name: "decimal", opt: "readbytes=4", want: "0123"},
		{name: "hex", opt: "readbytes=0x10", want: payload},
		{name: "octal", opt: "readbytes=010", want: "01234567"},
		{name: "zero-unlimited", opt: "readbytes=0", want: payload},
		{name: "negative", opt: "readbytes=-1", wantErr: true},
		{name: "garbage", opt: "readbytes=xyz", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parse.ParseSpec("PIPE," + tc.opt)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := ApplyReadBytes(spec, relay.FDStream{
				R:      strings.NewReader(payload),
				W:      io.Discard,
				C:      nopCloser{},
				CloseW: func() error { return nil },
			})
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(stream)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
