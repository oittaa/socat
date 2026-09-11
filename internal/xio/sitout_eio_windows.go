//go:build windows

package xio

import (
	"io"
	"time"
)

func wrapSitoutEIORead(r io.Reader, _ time.Duration) io.Reader { return r }
