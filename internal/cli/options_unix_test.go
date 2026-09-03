//go:build linux || darwin

package cli

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestTermiosOptionTypesAreValidated(t *testing.T) {
	tests := []struct {
		spec    string
		wantErr bool
	}{
		{spec: "PTY,echo"},
		{spec: "PTY,echo=0"},
		{spec: "PTY,echo=1"},
		{spec: "PTY,echo=false", wantErr: true},
		{spec: "PTY,echo=", wantErr: true},
		{spec: "PTY,raw"},
		{spec: "PTY,raw=0", wantErr: true},
		{spec: "PTY,b9600"},
		{spec: "PTY,b9600=0", wantErr: true},
		{spec: "PTY,vintr=3"},
		{spec: "PTY,vintr", wantErr: true},
		{spec: "PTY,ispeed=9600"},
		{spec: "PTY,ispeed=garbage", wantErr: true},
		{spec: "PTY,tiocswinsz=80:24"},
		{spec: "PTY,tiocswinsz", wantErr: true},
		{spec: "PTY,ctty=0"},
		{spec: "PTY,ctty=off", wantErr: true},
		{spec: "PTY,termios-setflags=0:1"},
		{spec: "PTY,termios-setflags=4:1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			s, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			err = validateSpecOptions(s)
			if tc.wantErr && err == nil {
				t.Fatal("validation succeeded")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validation failed: %v", err)
			}
		})
	}
}
