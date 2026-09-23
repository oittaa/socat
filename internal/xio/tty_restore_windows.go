//go:build windows

package xio

import "github.com/oittaa/socat/internal/addrconfig"

func AttachConfiguredTermios(_ *Opened, _ int, _ addrconfig.Terminal) error { return nil }
