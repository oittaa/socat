package netopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
)

func TestUnixBindTempnameLiteralOneIsNotDefault(t *testing.T) {
	_, err := resolveUnixBindConfig(addrconfig.Address{
		Network: addrconfig.Network{
			UnixBindTempname: addrconfig.OptionalString{Set: true, Value: "1"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "path pattern is not valid") {
		t.Fatalf("unix-bind-tempname=1: %v", err)
	}
}

func TestUnixBindTempnameOmittedUsesDefaultTemplate(t *testing.T) {
	got, err := resolveUnixBindConfig(addrconfig.Address{
		Network: addrconfig.Network{
			UnixBindTempname: addrconfig.OptionalString{Set: true, Omitted: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "/tmp/socat-bind."
	if !strings.HasPrefix(got, prefix) || len(got) != len(prefix)+6 {
		t.Fatalf("path=%q", got)
	}
}

func TestUnixBindTempnameEmptyUsesDefaultTemplate(t *testing.T) {
	got, err := resolveUnixBindConfig(addrconfig.Address{
		Network: addrconfig.Network{
			UnixBindTempname: addrconfig.OptionalString{Set: true, Value: ""},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "/tmp/socat-bind."
	if !strings.HasPrefix(got, prefix) || len(got) != len(prefix)+6 {
		t.Fatalf("path=%q", got)
	}
}
