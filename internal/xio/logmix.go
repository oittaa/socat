package xio

import "github.com/oittaa/socat/internal/relay"

// beginLogicalSession runs once per transfer session after both endpoints
// are open and before payload movement: -D dumps channel FDs, then -lm
// switches that session's logger to syslog.
func (g *Global) beginLogicalSession(left, right relay.Stream) {
	if g == nil {
		return
	}
	g.dumpSessionFDs(left, right)
	g.maybeSwitchMixedLog()
}

func (g *Global) maybeSwitchMixedLog() {
	if !g.LogMixed || g.Log == nil {
		return
	}
	g.Log.Infof("switching to syslog")
	if err := g.Log.UseSyslog(g.Progname, g.LogFacility); err != nil {
		g.Log.Errorf("%s", err)
		return
	}
	g.LogMixed = false
}
