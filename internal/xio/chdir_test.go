package xio

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func resolveChdirConfig(t *testing.T, spec parse.Spec) addrconfig.Address {
	t.Helper()
	kind := addrconfig.AddressKindOther
	switch spec.Type {
	case "CREATE", "CREAT":
		kind = addrconfig.AddressKindCREATE
	}
	config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: spec.Type, Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ResolvePreparedPaths(config)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestResolveChdirAddressPath(t *testing.T) {
	dir := t.TempDir()
	spec := parse.Spec{
		Type:    "CREATE",
		Params:  []string{"result.txt"},
		Options: []parse.Option{{Name: "chdir", Value: dir, Has: true}},
	}
	got := resolveChdirConfig(t, spec)
	if want := filepath.Join(dir, "result.txt"); got.File.Path != want {
		t.Fatalf("path=%q want %q", got.File.Path, want)
	}
	if spec.Params[0] != "result.txt" {
		t.Fatalf("input spec mutated: %q", spec.Params)
	}
	if got.Process.Chdir.Value != dir && !strings.HasPrefix(got.Process.Chdir.Value, dir) {
		t.Fatalf("chdir=%q want abs %q", got.Process.Chdir.Value, dir)
	}
}

func TestResolveChdirCDAlias(t *testing.T) {
	dir := t.TempDir()
	ch, err := parse.ParseChannel("CREATE:result.txt,cd=" + dir)
	if err != nil {
		t.Fatal(err)
	}
	got := resolveChdirConfig(t, *ch.Single)
	if want := filepath.Join(dir, "result.txt"); got.File.Path != want {
		t.Fatalf("path=%q want %q", got.File.Path, want)
	}
	if got.Process.Chdir.Value != dir && !filepath.IsAbs(got.Process.Chdir.Value) {
		t.Fatalf("chdir=%q want absolute directory", got.Process.Chdir.Value)
	}
}

func TestResolveChdirLockfileAndLink(t *testing.T) {
	dir := t.TempDir()
	spec := parse.Spec{
		Type:   "PTY",
		Params: []string{},
		Options: []parse.Option{
			{Name: "chdir", Value: dir, Has: true},
			{Name: "lockfile", Value: "rel.lock", Has: true},
			{Name: "link", Value: "slave.link", Has: true},
		},
	}
	got := resolveChdirConfig(t, spec)
	if got.File.LockPath != filepath.Join(dir, "rel.lock") {
		t.Fatalf("lock=%q", got.File.LockPath)
	}
	if got.Terminal.Link.Value != filepath.Join(dir, "slave.link") {
		t.Fatalf("link=%q", got.Terminal.Link.Value)
	}
}
