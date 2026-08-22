package main

import (
	"os"

	"github.com/oittaa/socat/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Exit))
}
