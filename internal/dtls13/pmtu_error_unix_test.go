//go:build linux || darwin

package dtls13

import "syscall"

func messageTooLongError() error {
	return syscall.EMSGSIZE
}
