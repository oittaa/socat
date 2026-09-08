package xio

import (
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestResolveChdirAddressPath(t *testing.T) {
	dir := t.TempDir()
	spec := parse.Spec{
		Type:    "CREATE",
		Params:  []string{"result.txt"},
		Options: []parse.Option{{Name: "chdir", Value: dir, Has: true}},
	}
	got, err := ResolveChdirPaths(spec)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "result.txt"); len(got.Params) != 1 || got.Params[0] != want {
		t.Fatalf("params=%q want [%q]", got.Params, want)
	}
	if spec.Params[0] != "result.txt" {
		t.Fatalf("input spec mutated: %q", spec.Params)
	}
}

func TestResolveChdirCDAlias(t *testing.T) {
	dir := t.TempDir()
	ch, err := parse.ParseChannel("CREATE:result.txt,cd=" + dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ResolveChdirPaths(*ch.Single)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "result.txt"); len(got.Params) != 1 || got.Params[0] != want {
		t.Fatalf("params=%q want [%q]", got.Params, want)
	}
	if got.OptionValue("chdir", "") != dir {
		t.Fatalf("chdir=%q want %q", got.OptionValue("chdir", ""), dir)
	}
}
