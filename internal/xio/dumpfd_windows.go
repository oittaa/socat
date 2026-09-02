//go:build windows

package xio

import "github.com/oittaa/socat/internal/relay"

func (g *Global) dumpSessionFDs(relay.Stream, relay.Stream) {}
