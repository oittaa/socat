package xio

import "os"

// socatMaxPids is the per-session registration cap for sighup/sigint/sigquit.
const socatMaxPids = 4

const (
	sigIdxHUP = iota
	sigIdxINT
	sigIdxQUIT
	sigIdxCount
)

// childSignalSession is the per-session four-slot table for sighup/sigint/
// sigquit. LISTEN,fork uses goroutines, so each forkSession owns a table.
// The Unix dispatcher aggregates live tables; other platforms never register.
type childSignalSession struct {
	n    [sigIdxCount]int
	pids [sigIdxCount][socatMaxPids]int
}

// ForwardRegisteredChildSignal forwards SIGHUP, SIGINT, and SIGQUIT after an
// EXEC/SYSTEM/SHELL address used those PARENT options.
//
// A true result means the caller must not terminate socat: the signal has
// been (or would be) kill()'d to registered child pids. False means socat
// still exits on the signal.
func ForwardRegisteredChildSignal(sig os.Signal) bool {
	return forwardRegisteredChildSignal(sig)
}
