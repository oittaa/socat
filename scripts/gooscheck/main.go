package main

import (
	"fmt"
	"os"
)

func main() {
	start := "."
	if len(os.Args) > 1 {
		start = os.Args[1]
	}
	root, err := findModuleRoot(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gooscheck: %v\n", err)
		os.Exit(2)
	}
	findings, err := scanTree(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gooscheck: %v\n", err)
		os.Exit(2)
	}
	if len(findings) == 0 {
		return
	}
	for _, f := range findings {
		fmt.Fprintln(os.Stderr, f)
	}
	fmt.Fprintf(os.Stderr, "gooscheck: %d unsupported GOOS constraint(s)\n", len(findings))
	os.Exit(1)
}
