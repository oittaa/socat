package netopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
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
	assertDefaultUnixBindTempname(t, addrconfig.Address{
		Network: addrconfig.Network{
			UnixBindTempname: addrconfig.OptionalString{Set: true, Omitted: true},
		},
	})
}

func TestUnixBindTempnameEmptyUsesDefaultTemplate(t *testing.T) {
	assertDefaultUnixBindTempname(t, addrconfig.Address{
		Network: addrconfig.Network{
			UnixBindTempname: addrconfig.OptionalString{Set: true, Value: ""},
		},
	})
}

func TestUnixBindTempnameEmptyWithChdirUsesDefaultTemplate(t *testing.T) {
	dir := t.TempDir()
	spec, err := parse.ParseSpec("UNIX-CONNECT:server.sock,unix-bind-tempname=,chdir=" + dir)
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(spec, addrconfig.Facts{
		Type: "UNIX-CONNECT",
		Kind: addrconfig.AddressKindUNIX,
		Role: addrconfig.AddressRoleConnect,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := xio.ResolvePreparedPaths(config)
	if err != nil {
		t.Fatal(err)
	}
	name := resolved.Network.UnixBindTempname
	if !name.Set || name.Omitted || name.Value != "" {
		t.Fatalf("tempname=%+v", name)
	}
	assertDefaultUnixBindTempname(t, resolved)
}

func assertDefaultUnixBindTempname(t *testing.T, config addrconfig.Address) {
	t.Helper()
	got, err := resolveUnixBindConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "/tmp/socat-bind."
	if !strings.HasPrefix(got, prefix) || len(got) != len(prefix)+6 {
		t.Fatalf("path=%q", got)
	}
}
