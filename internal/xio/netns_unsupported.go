//go:build darwin || windows

package xio

import "fmt"

// WithNetNS is a no-op unless netns= is set (Linux only).
func WithNetNS(name string, g *Global, fn func() error) error {
	if name == "" {
		return fn()
	}
	warnNetNSExperimental(g)
	return fmt.Errorf("netns is only supported on Linux")
}
