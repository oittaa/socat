package xio

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/oittaa/socat/internal/logx"
)

func TestNewSessionAndForkSessionOptions(t *testing.T) {
	printed := new(atomic.Bool)
	lg := logx.New()
	src := Options{BlockSize: 9}
	g := NewSession(src, lg)
	if g.childSignals == nil || g.sessionMu.Load() == nil {
		t.Fatal("NewSession owns sync/signals from create")
	}
	if g.Log != lg {
		t.Fatal("root session uses the provided logger")
	}
	src.BlockSize = 0
	if g.Options().BlockSize != 9 {
		t.Fatal("NewSession must not alias the caller's Options value")
	}
	snap := g.Options()
	snap.BlockSize = 0
	if g.Options().BlockSize != 9 {
		t.Fatal("Options() snapshot must not write session storage")
	}
	other := NewSession(Options{BlockSize: 9}, lg)
	if sharesOptions(other, g) {
		t.Fatal("separate NewSession calls must not share Options")
	}

	g.LogMixed = true
	g.Peer.SessionVars = map[string]string{"A": "1"}
	g.Peer.TLSVars = map[string]string{"B": "2"}
	g.statsPrinted = printed
	parentSig := g.childSignals
	parentMu := g.sessionMu.Load()

	c := g.ForkSession()
	c.Peer.SessionVars["A"] = "x"
	c.Peer.TLSVars["B"] = "y"
	c.LogMixed = false
	if !sharesOptions(c, g) {
		t.Fatal("fork must share private Options storage")
	}
	if c.Options().BlockSize != 9 || !c.ForkChild || c.statsPrinted != printed {
		t.Fatal("shared options, ForkChild set, stats shared")
	}
	if c.childSignals == nil || c.childSignals == parentSig {
		t.Fatal("child owns a distinct signal table")
	}
	if c.Log == nil || c.Log == lg || !g.LogMixed {
		t.Fatal("Log cloned, LogMixed copied per session")
	}
	if g.Peer.SessionVars["A"] != "1" || g.Peer.TLSVars["B"] != "2" {
		t.Fatal("peer maps must be cloned")
	}
	if c.sessionMu.Load() == nil || c.sessionMu.Load() == parentMu {
		t.Fatal("child owns a distinct session mutex")
	}
}

func TestForkSessionCopiesPeer(t *testing.T) {
	g := NewSession(Options{}, nil)
	g.Peer = Peer{
		SockAddr:    "10.0.0.1",
		PeerAddr:    "10.0.0.2",
		SockPort:    "1",
		PeerPort:    "2",
		TLSVars:     map[string]string{"CIPHER": "A"},
		SessionVars: map[string]string{"TIMESTAMP": "now"},
	}
	c := g.ForkSession()
	if c.Peer.SockAddr != "10.0.0.1" || c.Peer.PeerPort != "2" {
		t.Fatal("fork copies peer address strings")
	}
	c.Peer.SockAddr = "changed"
	c.Peer.PeerAddr = "changed"
	c.Peer.SessionVars["TIMESTAMP"] = "later"
	c.Peer.TLSVars["CIPHER"] = "B"
	if g.Peer.SockAddr != "10.0.0.1" || g.Peer.PeerAddr != "10.0.0.2" {
		t.Fatal("peer address strings are per-session")
	}
	if g.Peer.SessionVars["TIMESTAMP"] != "now" || g.Peer.TLSVars["CIPHER"] != "A" {
		t.Fatal("peer maps must be cloned")
	}
}

func TestForkSessionCopiesLogger(t *testing.T) {
	lg := logx.New()
	g := NewSession(Options{}, lg)
	g.LogMixed = true
	parentSig := g.childSignals

	c := g.ForkSession()
	if c.Log == nil || c.Log == g.Log || c.Log == lg {
		t.Fatal("fork must clone Log")
	}
	if !c.LogMixed {
		t.Fatal("LogMixed is copied")
	}
	if c.childSignals == nil || c.childSignals == parentSig || g.childSignals != parentSig {
		t.Fatal("child owns a fresh signal table; parent keeps its own")
	}
	c.LogMixed = false
	c.Log = logx.New()
	if !g.LogMixed || g.Log != lg {
		t.Fatal("parent logger is independent")
	}
}

func TestForkSessionCopiesChild(t *testing.T) {
	waitErr := errors.New("child wait")
	g := NewSession(Options{}, nil)
	g.Child = Child{ExitCode: 3, Err: waitErr}
	c := g.ForkSession()
	if c.Child.ExitCode != 3 || c.Child.Err != waitErr {
		t.Fatal("fork copies child wait status")
	}
	c.Child.ExitCode = 9
	c.Child.Err = nil
	if g.Child.ExitCode != 3 || g.Child.Err != waitErr {
		t.Fatal("child wait status is per-session")
	}
}

func TestForkSessionOwnsSniffFiles(t *testing.T) {
	parent, err := os.CreateTemp(t.TempDir(), "sniff-parent-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	if _, err := parent.WriteString("parent"); err != nil {
		t.Fatal(err)
	}

	g := NewSession(Options{RawLeftPath: parent.Name()}, nil)
	g.Sniff.RawLeft = parent
	c := g.ForkSession()
	if c.Sniff.RawLeft != nil || c.Sniff.RawRight != nil {
		t.Fatal("fork must not share sniff file pointers")
	}
	if g.Sniff.RawLeft != parent {
		t.Fatal("parent keeps its sniff files")
	}
	c.Sniff.closeFiles()
	if _, err := parent.WriteString("+still-open"); err != nil {
		t.Fatal(err)
	}
}

func TestForkSessionOwnsDistinctSessionMu(t *testing.T) {
	g := NewSession(Options{}, nil)
	SetSessionEnv(g, "A", "1")
	c := g.ForkSession()
	if g.sessionMu.Load() == nil || c.sessionMu.Load() == nil || g.sessionMu.Load() == c.sessionMu.Load() {
		t.Fatal("parent and child must own distinct SessionVars mutexes")
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			SetSessionEnv(g, "A", "p")
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			SetSessionEnv(c, "A", "c")
		}
	}()
	close(start)
	wg.Wait()
	if g.SessionVar("A") != "p" || c.SessionVar("A") != "c" {
		t.Fatal("parent and child SessionVars must stay independent")
	}
}

func TestForkSessionNilOwnsState(t *testing.T) {
	c := (*Global)(nil).ForkSession()
	if !c.ForkChild || c.options == nil || c.childSignals == nil || c.sessionMu.Load() == nil {
		t.Fatal("nil ForkSession still creates session-owned sync/signals and options")
	}
}
