package xio

import (
	"sync/atomic"
	"testing"
)

func TestForkSessionCopyShareReset(t *testing.T) {
	printed := new(atomic.Bool)
	g := &Global{BlockSize: 9, SessionVars: map[string]string{"A": "1"}, TLSVars: map[string]string{"B": "2"}, statsPrinted: printed, childSignals: new(childSignalSession)}
	c := g.forkSession()
	c.SessionVars["A"] = "x"
	c.TLSVars["B"] = "y"
	if c.BlockSize != 9 || !c.ForkChild || c.childSignals != nil || c.statsPrinted != printed {
		t.Fatal("options copied, ForkChild set, signals reset, stats shared")
	}
	if g.SessionVars["A"] != "1" || g.TLSVars["B"] != "2" {
		t.Fatal("peer maps must be cloned")
	}
}
