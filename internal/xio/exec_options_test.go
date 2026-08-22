//go:build unix

package xio

import (
	"strings"
	"testing"
)

func TestValidateProcessFDOptions(t *testing.T) {
	tests := []struct {
		name        string
		mode        Mode
		fdin, fdout string
		wantErr     string
	}{
		{name: "duplex", mode: ModeRDWR, fdin: "3", fdout: "4"},
		{name: "write-fdin", mode: ModeWrite, fdin: "3"},
		{name: "read-fdout", mode: ModeRead, fdout: "4"},
		{name: "write-fdout", mode: ModeWrite, fdout: "4", wantErr: "fdout"},
		{name: "read-fdin", mode: ModeRead, fdin: "3", wantErr: "fdin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProcessFDOptions(tt.mode, tt.fdin, tt.fdout)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error=%v want substring %q", err, tt.wantErr)
			}
		})
	}
}
