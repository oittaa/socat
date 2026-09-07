//go:build windows

package dtls13

import (
	"errors"
	"syscall"
)

const wsaEMSGSIZE syscall.Errno = 10040

func isMessageTooLong(err error) bool {
	return errors.Is(err, wsaEMSGSIZE)
}

func messageTooLongError() error {
	return wsaEMSGSIZE
}
