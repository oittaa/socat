//go:build windows

package xio

import (
	"github.com/oittaa/socat/internal/addrconfig"
)

func withConfiguredUmask(_ addrconfig.OptionalUint32, fn func() error) error { return fn() }
