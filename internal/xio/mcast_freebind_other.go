//go:build !linux

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

func applyFreebindFD(int, parse.Option) error {
	return fmt.Errorf("ip-freebind: not supported on this platform")
}

func applyTransparentFD(int, parse.Option) error {
	return fmt.Errorf("ip-transparent: not supported on this platform")
}
