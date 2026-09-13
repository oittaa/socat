package xio

import (
	"sync"
	"testing"
)

func TestForkSessionClonesSessionVarsUnderLock(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		g := NewSession(Options{}, nil)
		if initialized {
			SetSessionEnv(g, "LIVE", "initial")
		}
		var wg sync.WaitGroup
		wg.Go(func() {
			for range 100 {
				SetSessionEnv(g, "LIVE", "updated")
			}
		})
		for range 100 {
			_ = g.ForkSession().SessionVar("LIVE")
		}
		wg.Wait()
		if g.ForkSession().SessionVar("LIVE") != "updated" {
			t.Fatal("fork lost the session value")
		}
	}
}
