package xio

import (
	"sync/atomic"
	"testing"

	"github.com/oittaa/socat/internal/logx"
)

func TestForkSessionCopyShareReset(t *testing.T) {
	printed := new(atomic.Bool)
	lg := logx.New()
	g := &Global{
		BlockSize:    9,
		Log:          lg,
		LogMixed:     true,
		SessionVars:  map[string]string{"A": "1"},
		TLSVars:      map[string]string{"B": "2"},
		statsPrinted: printed,
		childSignals: new(childSignalSession),
	}
	c := g.ForkSession()
	c.SessionVars["A"] = "x"
	c.TLSVars["B"] = "y"
	c.LogMixed = false
	if c.BlockSize != 9 || !c.ForkChild || c.childSignals != nil || c.statsPrinted != printed {
		t.Fatal("options copied, ForkChild set, signals reset, stats shared")
	}
	if c.Log == nil || c.Log == lg || !g.LogMixed {
		t.Fatal("Log cloned, LogMixed copied per session")
	}
	if g.SessionVars["A"] != "1" || g.TLSVars["B"] != "2" {
		t.Fatal("peer maps must be cloned")
	}
}
