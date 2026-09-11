//go:build windows

package xio

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func WithUmask(_ parse.Spec, fn func() error) error { return fn() }

func withConfiguredUmask(_ addrconfig.OptionalUint32, fn func() error) error { return fn() }
