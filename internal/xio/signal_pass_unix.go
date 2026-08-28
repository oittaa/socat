//go:build unix

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

// socatMaxPids is classic SOCAT_MAXPIDS in xiosignal.c.
const socatMaxPids = 4

type childSigDesc struct {
	enabled bool // first registration installs pass-through for this signum
	n       int
	pids    [socatMaxPids]int
}

var (
	childSignalMu       sync.Mutex
	childSIGHUP         childSigDesc
	childSIGINT         childSigDesc
	childSIGQUIT        childSigDesc
	killRegisteredChild = func(pid int, sig syscall.Signal) error {
		return syscall.Kill(pid, sig)
	}
)

func childSigDescFor(sig syscall.Signal) *childSigDesc {
	switch sig {
	case syscall.SIGHUP:
		return &childSIGHUP
	case syscall.SIGINT:
		return &childSIGINT
	case syscall.SIGQUIT:
		return &childSIGQUIT
	default:
		return nil
	}
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
// applyopts walks remaining opts).
//
// Classic withfork+pipes also applies PH_LATE before fork while pid is still
// 0. kill(0, sig) would signal the process group. This port registers the
// real child pid after Start on every transport, including pipes, pty, and
// nofork (Go nofork still has a parent that Wait()s).
func registerExecParentSignals(s parse.Spec, cmd *exec.Cmd) error {
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
		if err := registerChildSignal(pid, sig); err != nil {
			return err
		}
	}
	return nil
}

func registerChildSignal(pid int, sig syscall.Signal) error {
	if pid <= 0 {
		return nil
	}
	childSignalMu.Lock()
	defer childSignalMu.Unlock()
	d := childSigDescFor(sig)
	if d == nil {
		return fmt.Errorf("sub process registered for unsupported signal")
	}
	if d.n >= socatMaxPids {
		return fmt.Errorf("too many sub processes registered for signal %d", int(sig))
	}
	d.enabled = true
	d.pids[d.n] = pid
	d.n++
	return nil
}

func unregisterChildSignals(pid int) {
	if pid <= 0 {
		return
	}
	childSignalMu.Lock()
	defer childSignalMu.Unlock()
	for _, d := range []*childSigDesc{&childSIGHUP, &childSIGINT, &childSIGQUIT} {
		j := 0
		for i := 0; i < d.n; i++ {
			if d.pids[i] != pid {
				d.pids[j] = d.pids[i]
				j++
			}
		}
		for i := j; i < d.n; i++ {
			d.pids[i] = 0
		}
		d.n = j
		// enabled stays set: classic never restores the default terminate
		// handler after the first xio_opt_signal.
	}
}

func forwardRegisteredChildSignal(sig os.Signal) bool {
	ss, ok := sig.(syscall.Signal)
	if !ok {
		return false
	}
	childSignalMu.Lock()
	d := childSigDescFor(ss)
	if d == nil || !d.enabled {
		childSignalMu.Unlock()
		return false
	}
	pids := d.pids
	n := d.n
	childSignalMu.Unlock()

	if log := logx.Default(); log != nil {
		log.Noticef("socatsignalpass(sig=%d)", int(ss))
	}
	sent := 0
	for i := 0; i < n; i++ {
		pid := pids[i]
		if pid == 0 {
			continue
		}
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
	childSIGHUP = childSigDesc{}
	childSIGINT = childSigDesc{}
	childSIGQUIT = childSigDesc{}
}

func childSignalPassStateForTest(sig syscall.Signal) (enabled bool, n int, pids []int) {
	childSignalMu.Lock()
	defer childSignalMu.Unlock()
	d := childSigDescFor(sig)
	if d == nil {
		return false, 0, nil
	}
	return d.enabled, d.n, append([]int(nil), d.pids[:d.n]...)
}
