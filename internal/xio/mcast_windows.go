//go:build windows

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
)

func applyPreparedMulticast(_ int, req addrconfig.MulticastRequest) error {
	name := req.Name
	if name == "" {
		name = "ip-add-membership"
	}
	return fmt.Errorf("%s: not supported on Windows", name)
}
