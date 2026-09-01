//go:build windows

package fileopen

import "github.com/oittaa/socat/internal/xio"

func setInheritedFDCloexec(int, *xio.Global) {}
