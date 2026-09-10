package cli

import "github.com/oittaa/socat/internal/xio"

// capTermios is used when stuffing xio.TermiosOptionNames into the CLI
// table for names that are not declared in optionmeta.
var capTermios = []string{xio.CapTermios}
