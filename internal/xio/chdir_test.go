package xio

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestResolveChdirPathsWithoutChangingProcessDirectory(t *testing.T) {
	before, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	spec := parse.Spec{
		Type:   "TLS-LISTEN",
		Params: []string{"443"},
		Options: []parse.Option{
			{Name: "chdir", Value: dir, Has: true},
			{Name: "cert", Value: "server.pem", Has: true},
			{Name: "cafile", Value: filepath.Join("trust", "ca.pem"), Has: true},
		},
	}
	got, err := ResolveChdirPaths(spec)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("process directory changed from %q to %q", before, after)
	}
	if value := got.OptionValue("chdir", ""); value != dir {
		t.Fatalf("chdir=%q want %q", value, dir)
	}
	if value := got.OptionValue("cert", ""); value != filepath.Join(dir, "server.pem") {
		t.Fatalf("cert=%q", value)
	}
	if value := got.OptionValue("cafile", ""); value != filepath.Join(dir, "trust", "ca.pem") {
		t.Fatalf("cafile=%q", value)
	}
}

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
