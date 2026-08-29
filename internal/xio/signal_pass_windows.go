//go:build windows

package xio

import "os"

func forwardRegisteredChildSignal(os.Signal) bool { return false }
