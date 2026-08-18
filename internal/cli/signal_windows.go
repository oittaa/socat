//go:build windows

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyExitSignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}

func notifyStatsSignal(chan<- os.Signal) {}
