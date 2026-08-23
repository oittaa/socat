//go:build windows

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

func defaultSignalLogMask() uint64 {
	return uint64(1)<<uint(os.Interrupt.(syscall.Signal)) | uint64(1)<<uint(syscall.SIGTERM)
}

func notifyExitSignals(ch chan<- os.Signal, _ uint64) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}

func notifyStatsSignal(chan<- os.Signal) {}
