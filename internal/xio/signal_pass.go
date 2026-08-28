package xio

import "os"

// ForwardRegisteredChildSignal implements classic socatsignalpass for SIGHUP,
// SIGINT, and SIGQUIT after an EXEC/SYSTEM/SHELL address used those PARENT
// options (xiosignal.c at tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same).
//
// When this returns true, the caller must not terminate socat: the signal has
// been (or would be) kill()'d to registered child pids. When it returns false,
// the default EXITCODESIG* path still applies.
func ForwardRegisteredChildSignal(sig os.Signal) bool {
	return forwardRegisteredChildSignal(sig)
}
