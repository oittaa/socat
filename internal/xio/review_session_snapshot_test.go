package xio

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
)

// TestForkSessionClonesSessionVarsUnderLock fails with concurrent map
// iteration and map write if ForkSession copies the SessionVars header
// under lock and then clones after unlock.
func TestForkSessionClonesSessionVarsUnderLock(t *testing.T) {
	g := NewSession(Options{}, nil)
	for i := 0; i < 16; i++ {
		SetSessionEnv(g, fmt.Sprintf("STABLE%d", i), "v")
	}
	SetSessionEnv(g, "LIVE", "0")

	var writer sync.WaitGroup
	writer.Add(1)
	start := make(chan struct{})
	go func() {
		defer writer.Done()
		<-start
		for i := 0; i < 20000; i++ {
			SetSessionEnv(g, "LIVE", strconv.Itoa(i))
		}
	}()
	close(start)
	for i := 0; i < 20000; i++ {
		c := g.ForkSession()
		if c.SessionVar("STABLE0") != "v" {
			t.Fatal("stable SessionVars entry was not cloned")
		}
		_ = c.SessionVar("LIVE")
	}
	writer.Wait()
}

// TestForkSessionClonesNilSessionVarsUnderLock starts with a nil SessionVars
// map. A Peer struct copy would race with the first SetSessionEnv write of
// that header even if the later clone is locked.
func TestForkSessionClonesNilSessionVarsUnderLock(t *testing.T) {
	g := NewSession(Options{}, nil)
	if g.Peer.SessionVars != nil {
		t.Fatal("NewSession must start with nil SessionVars")
	}

	var writer sync.WaitGroup
	writer.Add(1)
	start := make(chan struct{})
	go func() {
		defer writer.Done()
		<-start
		for i := 0; i < 20000; i++ {
			SetSessionEnv(g, "LIVE", strconv.Itoa(i))
		}
	}()
	close(start)
	for i := 0; i < 20000; i++ {
		c := g.ForkSession()
		_ = c.SessionVar("LIVE")
	}
	writer.Wait()
}
