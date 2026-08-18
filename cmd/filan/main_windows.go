//go:build windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "filan is not supported on Windows")
	os.Exit(1)
}
