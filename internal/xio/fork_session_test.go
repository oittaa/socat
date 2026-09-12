package xio

import (
	"sync/atomic"
	"testing"

	"github.com/oittaa/socat/internal/logx"
)

func TestNewSessionAndForkSessionOptions(t *testing.T) {
	printed := new(atomic.Bool)
	lg := logx.New()
	src := Options{BlockSize: 9}
	g := NewSession(src, lg)
	if g.childSignals != nil || g.sessionMu.Load() != nil {
		t.Fatal("NewSession owns empty sync/signals")
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
	if other.sharesOptions(g) {
		t.Fatal("separate NewSession calls must not share Options")
	}

	g.LogMixed = true
	g.Peer.SessionVars = map[string]string{"A": "1"}
	g.Peer.TLSVars = map[string]string{"B": "2"}
	g.statsPrinted = printed
	g.childSignals = new(childSignalSession)

	c := g.ForkSession()
	c.Peer.SessionVars["A"] = "x"
	c.Peer.TLSVars["B"] = "y"
	c.LogMixed = false
	if !c.sharesOptions(g) {
		t.Fatal("fork must share private Options storage")
	}
	if c.Options().BlockSize != 9 || !c.ForkChild || c.childSignals != nil || c.statsPrinted != printed {
		t.Fatal("shared options, ForkChild set, signals reset, stats shared")
	}
	if c.Log == nil || c.Log == lg || !g.LogMixed {
		t.Fatal("Log cloned, LogMixed copied per session")
	}
	if g.Peer.SessionVars["A"] != "1" || g.Peer.TLSVars["B"] != "2" {
		t.Fatal("peer maps must be cloned")
	}
	if c.sessionMu.Load() != nil {
		t.Fatal("child mutex starts unset")
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

func TestForkSessionNilOwnsState(t *testing.T) {
	c := (*Global)(nil).ForkSession()
	if !c.ForkChild || c.options == nil || c.childSignals != nil || c.sessionMu.Load() != nil {
		t.Fatal("nil ForkSession still creates session-owned sync/signals and options")
	}
}
