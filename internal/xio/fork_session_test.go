package xio

import (
	"errors"
	"testing"

	"github.com/oittaa/socat/internal/logx"
)

func TestNewSessionAndForkSessionOptions(t *testing.T) {
	src := Options{BlockSize: 9}
	parent := NewSession(src, nil)
	child := parent.ForkSession()
	src.BlockSize = 0
	snapshot := child.Options()
	snapshot.BlockSize = 0
	if parent.Options().BlockSize != 9 || child.Options().BlockSize != 9 {
		t.Fatal("caller changed session options")
	}
	if child.options != parent.options || !child.ForkChild {
		t.Fatal("fork must share immutable options and mark the child")
	}
	if child.childSignals == parent.childSignals || child.childSignals == nil {
		t.Fatal("fork shared child signal state")
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
	parent := NewSession(Options{}, logx.New())
	parent.LogMixed = true
	child := parent.ForkSession()
	if child.Log == nil || child.Log == parent.Log || !child.LogMixed {
		t.Fatal("fork did not copy logger configuration")
	}
	child.LogMixed = false
	if !parent.LogMixed {
		t.Fatal("child changed parent logging")
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

func TestForkSessionOwnsDistinctSessionMu(t *testing.T) {
	parent := NewSession(Options{}, nil)
	child := parent.ForkSession()
	if parent.sessionMu.Load() == nil || child.sessionMu.Load() == nil || parent.sessionMu.Load() == child.sessionMu.Load() {
		t.Fatal("parent and child share a session mutex")
	}
}

func TestForkSessionNilOwnsState(t *testing.T) {
	c := (*Global)(nil).ForkSession()
	if !c.ForkChild || c.options == nil || c.childSignals == nil || c.sessionMu.Load() == nil {
		t.Fatal("nil ForkSession still creates session-owned sync/signals and options")
	}
}
