package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseDurationRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{"", "banana", "NaN", "+Inf", "1e100"} {
		if _, err := parseDuration(value); err == nil {
			t.Errorf("parseDuration(%q) succeeded", value)
		}
	}
	for _, value := range []string{"1", "1.5", "250ms", "-1"} {
		if _, err := parseDuration(value); err != nil {
			t.Errorf("parseDuration(%q): %v", value, err)
		}
	}
}

func TestParseArgsRejectsMalformedTimeouts(t *testing.T) {
	for _, args := range [][]string{{"-tbanana"}, {"-Tbanana"}} {
		if _, err := ParseArgs(args); err == nil {
			t.Fatalf("ParseArgs(%q) succeeded", args)
		}
	}
}

func TestValidateAddressOptions(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantErr string
	}{
		{name: "known", spec: "CREATE:file,perm=600"},
		{name: "known-alias", spec: "TCP-LISTEN:1,so-reuseaddr"},
		{name: "unknown", spec: "CREATE:file,totally-unknown=1", wantErr: "unknown option"},
		{name: "bad-perm", spec: "CREATE:file,perm=xyz", wantErr: "invalid perm"},
		{name: "bad-duration", spec: "TCP:localhost:1,connect-timeout=soon", wantErr: "invalid connect-timeout"},
		{name: "bad-children", spec: "TCP-LISTEN:1,fork,max-children=many", wantErr: "invalid max-children"},
		{name: "bad-socktype", spec: "UNIX:file,socktype=stream", wantErr: "invalid socktype"},
		{name: "bad-ftruncate", spec: "OPEN:file,ftruncate=-1", wantErr: "invalid ftruncate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch, err := parse.ParseChannel(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			err = validateChannelOptions(ch)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error=%v want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestAddressDurationUsesCLIUnits(t *testing.T) {
	o := parse.Option{Name: "connect-timeout", Value: "0.25", Has: true}
	if err := validateAddressOptionValue(o); err != nil {
		t.Fatal(err)
	}
	d, err := parseDuration(o.Value)
	if err != nil || d != 250*time.Millisecond {
		t.Fatalf("duration=%v err=%v", d, err)
	}
}
