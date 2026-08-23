//go:build unix

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

func defaultSignalLogMask() uint64 {
	var mask uint64
	for _, sig := range []syscall.Signal{
		syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGILL,
		syscall.SIGABRT, syscall.SIGBUS, syscall.SIGFPE, syscall.SIGSEGV, syscall.SIGTERM,
	} {
		mask |= uint64(1) << uint(sig)
	}
	return mask
}

func notifyExitSignals(ch chan<- os.Signal, logMask uint64) {
	signals := []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGILL, syscall.SIGQUIT, syscall.SIGHUP}
	for number := 1; number < 64; number++ {
		if logMask&(uint64(1)<<uint(number)) == 0 || number == int(syscall.SIGKILL) || number == int(syscall.SIGSTOP) {
			continue
		}
		signals = append(signals, syscall.Signal(number))
	}
	signal.Notify(ch, signals...)
}

func notifyStatsSignal(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGUSR1)
}
