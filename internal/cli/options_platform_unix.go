//go:build linux || darwin

package cli

import "github.com/oittaa/socat/internal/parse"

func validateUnixTightSocklen(option parse.Option) error {
	return validateOptionalBool(option)
}
