// Command fuzzall runs native Go fuzz targets one at a time.
// GitHub CI does not invoke this. Use it on a local Linux, macOS, or Windows host:
//
//	go run ./scripts/fuzzall
//	go run ./scripts/fuzzall -fuzztime=5m
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type target struct {
	pkg      string
	name     string
	unixOnly bool
}

var targets = []target{
	{pkg: "./internal/parse", name: "FuzzParseSpec"},
	{pkg: "./internal/parse", name: "FuzzParseChannel"},
	{pkg: "./internal/cli", name: "FuzzParseArgs"},
	{pkg: "./internal/cli", name: "FuzzValidateChannelOptions"},
	{pkg: "./internal/xio", name: "FuzzParseSocatData"},
	{pkg: "./internal/xio", name: "FuzzParseTimeval"},
	{pkg: "./internal/xio", name: "FuzzParsePositiveInt"},
	{pkg: "./internal/xio", name: "FuzzParseHexOpt", unixOnly: true},
	{pkg: "./internal/xio/wsopen", name: "FuzzWSTarget"},
	{pkg: "./internal/xio/quicopen", name: "FuzzQUICTarget"},
	{pkg: "./internal/xio/proxyopen", name: "FuzzProxyStatusOK"},
	{pkg: "./internal/xio/proxyopen", name: "FuzzProxyResponseLine"},
	{pkg: "./internal/xio/proxyopen", name: "FuzzSOCKS4Reply"},
	{pkg: "./internal/xio/proxyopen", name: "FuzzSOCKS5Reply"},
}

func main() {
	fuzztime := flag.String("fuzztime", "30s", "duration per fuzz target")
	flag.Parse()
	if _, err := time.ParseDuration(*fuzztime); err != nil {
		fmt.Fprintf(os.Stderr, "invalid -fuzztime %q: %v\n", *fuzztime, err)
		os.Exit(2)
	}

	root, err := moduleRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fuzzall: %v\n", err)
		os.Exit(2)
	}

	failed := 0
	for _, tgt := range targets {
		if tgt.unixOnly && runtime.GOOS == "windows" {
			fmt.Printf("skip %s %s (unix only)\n", tgt.pkg, tgt.name)
			continue
		}
		fmt.Printf("==> %s %s\n", tgt.pkg, tgt.name)
		cmd := exec.Command("go", "test", tgt.pkg, "-run=^$", "-fuzz="+tgt.name, "-fuzztime="+*fuzztime) // #nosec G204 -- argv is a fixed target table plus a parsed duration
		cmd.Dir = root
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s %s: %v\n", tgt.pkg, tgt.name, err)
			failed++
		}
	}
	if failed > 0 {
		os.Exit(1)
	}
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", dir)
		}
		dir = parent
	}
}
