//go:build linux || darwin

package dtls13

import (
	"errors"
	"syscall"
)

func isMessageTooLong(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE)
}
