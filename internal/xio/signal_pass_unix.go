//go:build linux || darwin

package xio

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

// liveSessions holds every per-logical-process OFUNC_SIGNAL table that
// currently has a pid (classic xiosignal.c at tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same). LISTEN,fork uses
// goroutines, so each forkSession Global owns a table; the process handler
// aggregates every live table's pids.
var (
	childSignalMu       sync.Mutex
	processSession      childSignalSession
	liveSessions        = map[*childSignalSession]struct{}{}
	killRegisteredChild = func(pid int, sig syscall.Signal) error {
		return syscall.Kill(pid, sig)
	}
)

func sigIndex(sig syscall.Signal) (int, bool) {
	switch sig {
	case syscall.SIGHUP:
		return sigIdxHUP, true
	case syscall.SIGINT:
		return sigIdxINT, true
	case syscall.SIGQUIT:
		return sigIdxQUIT, true
	default:
		return 0, false
	}
}

func sessionForLocked(g *Global) *childSignalSession {
	if g == nil {
		return &processSession
	}
	if g.childSignals == nil {
		g.childSignals = &childSignalSession{}
	}
	return g.childSignals
}

func parentSignalName(o parse.Option) (syscall.Signal, bool) {
	switch strings.ToLower(o.Name) {
	case "sighup":
		return syscall.SIGHUP, true
	case "sigint":
		return syscall.SIGINT, true
	case "sigquit":
		return syscall.SIGQUIT, true
	default:
		return 0, false
	}
}

func execParentSignalRequested(s parse.Spec) bool {
	// Named lookups keep the option-table contract pointed at these spellings.
	return s.HasOption("sighup") || s.HasOption("sigint") || s.HasOption("sigquit")
}

// validateExecParentSignals is classic TYPE_CONST: any assignment is
// "no value permitted" (parseopts_table), including sighup=0.
func validateExecParentSignals(s parse.Spec) error {
	_ = execParentSignalRequested(s)
	for _, o := range s.Options {
		if _, ok := parentSignalName(o); !ok {
			continue
		}
		if o.Has {
			return fmt.Errorf("%s: no value permitted", o.OriginalSpelling())
		}
	}
	return nil
}

// registerExecParentSignals is classic PH_LATE OFUNC_SIGNAL after
// sfd->para.exec.pid = pid (xio-progcall.c / xioopts.c applyopt, same SHAs as
// ForwardRegisteredChildSignal). Each occurrence registers once, so two
// `sighup` flags on one address occupy two of the four slots (classic
// applyopts walks remaining opts). The four-slot limit is per logical session
// (classic per-process table). g's forkSession copy is that session.
//
// Classic withfork+pipes also applies PH_LATE before fork while pid is still
// 0. kill(0, sig) would signal the process group. This port registers the
// real child pid after Start on every transport, including pipes, pty, and
// nofork (Go nofork still has a parent that Wait()s).
func registerExecParentSignals(s parse.Spec, cmd *exec.Cmd, g *Global) error {
	if err := validateExecParentSignals(s); err != nil {
		return err
	}
	if !execParentSignalRequested(s) {
		return nil
	}
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	pid := cmd.Process.Pid
	for _, o := range s.Options {
		sig, ok := parentSignalName(o)
		if !ok {
			continue
		}
		if err := registerChildSignalOn(g, pid, sig); err != nil {
			return err
		}
	}
	return nil
}

func registerChildSignal(pid int, sig syscall.Signal) error {
	return registerChildSignalOn(nil, pid, sig)
}

func registerChildSignalOn(g *Global, pid int, sig syscall.Signal) error {
	if pid <= 0 {
		return nil
	}
	childSignalMu.Lock()
	defer childSignalMu.Unlock()
	idx, ok := sigIndex(sig)
	if !ok {
		return fmt.Errorf("sub process registered for unsupported signal")
	}
	sess := sessionForLocked(g)
	if sess.n[idx] >= socatMaxPids {
		return fmt.Errorf("too many sub processes registered for signal %d", int(sig))
	}
	sess.pids[idx][sess.n[idx]] = pid
	sess.n[idx]++
	liveSessions[sess] = struct{}{}
	return nil
}

func unregisterChildSignals(pid int) {
	if pid <= 0 {
		return
	}
	childSignalMu.Lock()
	defer childSignalMu.Unlock()
	for sess := range liveSessions {
		for idx := 0; idx < sigIdxCount; idx++ {
			j := 0
			for i := 0; i < sess.n[idx]; i++ {
				if sess.pids[idx][i] != pid {
					sess.pids[idx][j] = sess.pids[idx][i]
					j++
				}
			}
			for i := j; i < sess.n[idx]; i++ {
				sess.pids[idx][i] = 0
			}
			sess.n[idx] = j
		}
		if sessionEmpty(sess) {
			delete(liveSessions, sess)
		}
	}
}

func sessionEmpty(s *childSignalSession) bool {
	for idx := 0; idx < sigIdxCount; idx++ {
		if s.n[idx] > 0 {
			return false
		}
	}
	return true
}

func collectPidsLocked(idx int) []int {
	var pids []int
	for sess := range liveSessions {
		for i := 0; i < sess.n[idx]; i++ {
			if pid := sess.pids[idx][i]; pid != 0 {
				pids = append(pids, pid)
			}
		}
	}
	return pids
}

func forwardRegisteredChildSignal(sig os.Signal) bool {
	ss, ok := sig.(syscall.Signal)
	if !ok {
		return false
	}
	idx, ok := sigIndex(ss)
	if !ok {
		return false
	}
	childSignalMu.Lock()
	pids := collectPidsLocked(idx)
	childSignalMu.Unlock()
	// Pass-through only while at least one pid is registered. Classic
	// socatsignalpass stays installed for the life of the process, but that
	// process is a fork(2) worker. This port's listener shares the process
	// with goroutine sessions, so an empty table restores terminate-on-signal
	// like classic's listener parent.
	if len(pids) == 0 {
		return false
	}

	if log := logx.Default(); log != nil {
		log.Noticef("socatsignalpass(sig=%d)", int(ss))
	}
	sent := 0
	for _, pid := range pids {
		sent++
		if err := killRegisteredChild(pid, ss); err != nil {
			if log := logx.Default(); log != nil {
				log.Warningf("kill(%d, %d): %s", pid, int(ss), err)
			}
		}
	}
	if log := logx.Default(); log != nil {
		log.Infof("socatsignalpass(): propagated signal to %d sub processes", sent)
	}
	return true
}

func resetChildSignalPassForTest() {
	childSignalMu.Lock()
	defer childSignalMu.Unlock()
	processSession = childSignalSession{}
	liveSessions = map[*childSignalSession]struct{}{}
}

func childSignalPassStateForTest(sig syscall.Signal) (enabled bool, n int, pids []int) {
	childSignalMu.Lock()
	defer childSignalMu.Unlock()
	idx, ok := sigIndex(sig)
	if !ok {
		return false, 0, nil
	}
	pids = collectPidsLocked(idx)
	n = len(pids)
	return n > 0, n, pids
}
