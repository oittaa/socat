//go:build !linux

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// WithNetNS is a no-op unless netns= is set (Linux only).
func WithNetNS(s parse.Spec, g *Global, fn func() error) error {
	if _, ok := netnsName(s); !ok {
		return fn()
	}
	warnNetNSExperimental(g)
	return fmt.Errorf("netns is only supported on Linux")
}
