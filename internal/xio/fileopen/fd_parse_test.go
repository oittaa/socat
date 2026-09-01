package fileopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseFDNum(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		params []string
		want   int
		errSub string
	}{
		{name: "decimal", raw: "FD:10", want: 10},
		{name: "hex", raw: "FD:0x10", want: 16},
		{name: "octal", raw: "FD:010", want: 8},
		{name: "implicit-digits", raw: "3", want: 3},
		{name: "leftover", raw: "FD:10foo", errSub: `error in FD number "10foo"`},
		{name: "hex-incomplete", raw: "FD:0x", errSub: `error in FD number "0x"`},
		{name: "negative", raw: "FD:-1", errSub: `error in FD number "-1"`},
		{name: "missing", raw: "FD", errSub: "wrong number of parameters"},
		{name: "empty-param", params: []string{""}, errSub: "wrong number of parameters"},
		{name: "extra-params", raw: "FD:1:2", errSub: "wrong number of parameters"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var spec parse.Spec
			if tc.raw != "" {
				parsed, err := parse.ParseSpec(tc.raw)
				if err != nil {
					t.Fatal(err)
				}
				spec = parsed
			} else {
				spec = parse.Spec{Type: "FD", Params: tc.params}
			}
			n, err := parseFDNum(spec)
			if tc.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("error=%v want %q", err, tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if n != tc.want {
				t.Fatalf("fd=%d want %d", n, tc.want)
			}
		})
	}
}

func TestParseAcceptFDNumSharesParser(t *testing.T) {
	spec, err := parse.ParseSpec("ACCEPT-FD:0x20")
	if err != nil {
		t.Fatal(err)
	}
	n, err := parseFDNum(spec)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatalf("fd=%d want 32", n)
	}
}
