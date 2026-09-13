// Command fuzzall runs native Go fuzz targets one at a time.
// Weekly and manually dispatched GitHub workflows invoke this runner
// (.github/workflows/deep-tests.yml). Ordinary `go test` still runs seed
// cases on every PR. Use it locally with:
//
//	go run ./scripts/fuzzall
//	go run ./scripts/fuzzall -fuzztime=5m
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

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

	list := exec.Command("go", "test", "-json", "-list=^Fuzz", "./...")
	list.Dir = root
	list.Stderr = os.Stderr
	out, err := list.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fuzzall: discover targets: %v\n%s", err, out)
		os.Exit(1)
	}

	failed := 0
	decoder := json.NewDecoder(bytes.NewReader(out))
	for {
		var event struct {
			Action, Package, Output string
		}
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "fuzzall: decode target list: %v\n", err)
			os.Exit(1)
		}
		name := strings.TrimSpace(event.Output)
		if event.Action != "output" || !strings.HasPrefix(name, "Fuzz") {
			continue
		}
		fmt.Printf("==> %s %s\n", event.Package, name)
		cmd := exec.Command("go", "test", event.Package, "-run=^$", "-fuzz=^"+name+"$", "-fuzztime="+*fuzztime) // #nosec G204 -- package and target come from go test discovery; duration is parsed above
		cmd.Dir = root
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s %s: %v\n", event.Package, name, err)
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
