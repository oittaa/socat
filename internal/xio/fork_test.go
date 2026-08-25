package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestForkLimits(t *testing.T) {
	cases := []struct {
		name            string
		spec            string
		wantFork        bool
		wantMaxChildren int
		wantErr         string
	}{
		{name: "plain", spec: "TCP4-LISTEN:0"},
		{name: "fork", spec: "TCP4-LISTEN:0,fork", wantFork: true},
		{
			name:            "fork-max-children",
			spec:            "TCP4-LISTEN:0,fork,max-children=5",
			wantFork:        true,
			wantMaxChildren: 5,
		},
		{
			name:            "hex-max-children",
			spec:            "TCP4-LISTEN:0,fork,max-children=0x10",
			wantFork:        true,
			wantMaxChildren: 16,
		},
		{
			name:            "octal-max-children",
			spec:            "TCP4-LISTEN:0,fork,max-children=010",
			wantFork:        true,
			wantMaxChildren: 8,
		},
		{
			name:    "trailing-junk",
			spec:    "TCP4-LISTEN:0,fork,max-children=5abc",
			wantErr: `invalid max-children "5abc"`,
		},
		{
			name:    "invalid-value",
			spec:    "TCP4-LISTEN:0,fork,max-children=abc",
			wantErr: `invalid max-children "abc"`,
		},
		{
			name:    "zero-value",
			spec:    "TCP4-LISTEN:0,fork,max-children=0",
			wantErr: `invalid max-children "0"`,
		},
		{
			name:    "negative-value",
			spec:    "TCP4-LISTEN:0,fork,max-children=-2",
			wantErr: `invalid max-children "-2"`,
		},
		{
			name:    "without-fork",
			spec:    "TCP4-LISTEN:0,max-children=3",
			wantErr: "option max-children not allowed without option fork",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			fork, maxChildren, err := ForkLimits(spec)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fork != tc.wantFork || maxChildren != tc.wantMaxChildren {
				t.Fatalf("fork=%v maxChildren=%d, want %v/%d", fork, maxChildren, tc.wantFork, tc.wantMaxChildren)
			}
		})
	}
}
