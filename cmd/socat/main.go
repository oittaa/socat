package main

import (
	"os"

	"github.com/oittaa/socat/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
