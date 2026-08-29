//go:build darwin

package main

import (
	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

func printLinuxSockopts(*outbuf.Buf, int) {}

func socketProtocol(int) (int, error) {
	return -1, unix.ENOPROTOOPT
}
