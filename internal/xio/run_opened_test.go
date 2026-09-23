package xio

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/relay"
)

var errDispatch = errors.New("dispatch")

type recordListener struct{ calls int }

func (l *recordListener) Accept() (net.Conn, error) { l.calls++; return nil, errDispatch }
func (l *recordListener) Close() error              { return nil }
func (l *recordListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestRunOpenedDispatch(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		left, dial, canceled bool
	}{
		{"left accept", true, false, false},
		{"left dial", true, true, false},
		{"right accept", false, false, false},
		{"right dial", false, true, false},
		{"canceled left dial", true, true, true},
		{"canceled right dial", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := NewSession(Options{}, nil)
			listener := &recordListener{}
			var opened *Opened
			var err error
			if tc.dial {
				opened, err = NewRepeatedDial("dial", RepeatedDial{Dial: func(context.Context) (net.Conn, error) {
					listener.calls++
					return nil, errDispatch
				}})
			} else {
				opened, err = NewAcceptParent("accept", AcceptParent{Listener: listener})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = opened.Close() }()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			if tc.left {
				err = RunOpenedPrepared(ctx, opened, preparedChannel{}, session)
			} else {
				ready, createErr := NewReady("left", relay.FDStream{})
				if createErr != nil {
					t.Fatal(createErr)
				}
				defer func() { _ = ready.Close() }()
				err = runOpenedPair(ctx, ready, opened, session, ModeRDWR)
			}
			if tc.canceled {
				if err != nil || listener.calls != 0 {
					t.Fatalf("canceled run: error=%v calls=%d", err, listener.calls)
				}
			} else if !errors.Is(err, errDispatch) || listener.calls != 1 {
				t.Fatalf("dispatch: error=%v calls=%d", err, listener.calls)
			}
		})
	}
}
