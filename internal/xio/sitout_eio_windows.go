//go:build windows

package xio

import (
	"fmt"
	"io"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// SitoutEIO is classic PTY sitout-eio. Windows has no PTY master EIO path;
// reject the option instead of ignoring it.
func SitoutEIO(s parse.Spec) (time.Duration, error) {
	if s.HasOption("sitout-eio") {
		return 0, fmt.Errorf("sitout-eio: not supported on this platform")
	}
	return 0, nil
}

func wrapSitoutEIORead(r io.Reader, _ time.Duration) io.Reader { return r }
