//go:build unix

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyExitSignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGILL, syscall.SIGQUIT, syscall.SIGHUP)
}

func notifyStatsSignal(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGUSR1)
}
