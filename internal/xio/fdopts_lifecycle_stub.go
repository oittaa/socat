//go:build !unix

package xio

import (
	"os"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func applyFDLifecycleToFile(_ *os.File, _ parse.Spec) error { return nil }

func applyFDLifecycleToStream(_ parse.Spec, _ relay.Stream) error { return nil }

func hasFDLifecycleOptions(_ parse.Spec) bool { return false }
