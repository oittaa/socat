//go:build linux

package netopen

import "golang.org/x/sys/unix"

const sockCloexec = unix.SOCK_CLOEXEC
