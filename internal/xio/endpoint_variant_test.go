package xio

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/relay"
)

func TestOpenedVariantFieldsUnexported(t *testing.T) {
	rt := reflect.TypeOf(Opened{})
	forbidden := []string{
		"Kind", "Stream", "Read", "Write", "Listener", "Dial", "NoForkConfig",
		"ForkSocketpair", "PeerFilter", "AcceptTimeout", "Interval",
		"MaxChildren", "ChildrenShutup", "WrapDial", "HandshakeTimeout",
	}
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		for _, field := range forbidden {
			if name == field {
				t.Errorf("Opened.%s is exported; variant data must stay in private payloads", name)
			}
		}
	}
}

func TestOpenedConstructorsExclusive(t *testing.T) {
	stream := relay.FDStream{}
	ln := newCloseOnlyListener()
	t.Cleanup(func() { _ = ln.Close() })
	dial := func(context.Context) (net.Conn, error) { return nil, net.ErrClosed }
	wrap := func(net.Conn) (relay.Stream, error) { return relay.NetStream{}, nil }
	cfg := addrconfig.Address{Type: "EXEC"}

	ready, err := NewReady("ready", stream)
	if err != nil {
		t.Fatal(err)
	}
	if ready.Kind() != KindReady {
		t.Fatalf("ready Kind=%v", ready.Kind())
	}
	if ready.Stream() == nil || ready.Listener() != nil || ready.Dial() != nil || ready.NoForkConfig() != nil {
		t.Fatalf("ready leaked non-ready payload")
	}

	accept, err := NewAcceptParent("accept", AcceptParent{Listener: ln, WrapDial: wrap, MaxChildren: 2})
	if err != nil {
		t.Fatal(err)
	}
	if accept.Kind() != KindListen {
		t.Fatalf("accept Kind=%v", accept.Kind())
	}
	if accept.Listener() == nil || accept.Stream() != nil || accept.Dial() != nil || accept.NoForkConfig() != nil {
		t.Fatalf("accept leaked non-accept payload")
	}
	if accept.MaxChildren() != 2 {
		t.Fatalf("accept MaxChildren=%d", accept.MaxChildren())
	}

	parent, err := NewRepeatedDial("dial", RepeatedDial{Dial: dial, WrapDial: wrap, Interval: 1})
	if err != nil {
		t.Fatal(err)
	}
	if parent.Kind() != KindDial {
		t.Fatalf("dial Kind=%v", parent.Kind())
	}
	if parent.Dial() == nil || parent.Stream() != nil || parent.Listener() != nil || parent.NoForkConfig() != nil {
		t.Fatalf("dial leaked non-dial payload")
	}

	nofork := NewDeferredNoFork("nofork", cfg)
	if nofork.Kind() != KindExec {
		t.Fatalf("nofork Kind=%v", nofork.Kind())
	}
	if nofork.NoForkConfig() == nil || nofork.Stream() != nil || nofork.Listener() != nil || nofork.Dial() != nil {
		t.Fatalf("nofork leaked non-nofork payload")
	}
	if nofork.NoForkConfig().Type != "EXEC" {
		t.Fatalf("nofork type=%q", nofork.NoForkConfig().Type)
	}
}

func TestSetChildrenShutupOnlyOnParents(t *testing.T) {
	ready, err := NewReady("ready", relay.FDStream{})
	if err != nil {
		t.Fatal(err)
	}
	ready.SetChildrenShutup(3)
	if ready.ChildrenShutup() != 0 {
		t.Fatalf("ready ChildrenShutup=%d", ready.ChildrenShutup())
	}

	accept, err := NewAcceptParent("accept", AcceptParent{Listener: newCloseOnlyListener()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accept.Close() })
	accept.SetChildrenShutup(4)
	if accept.ChildrenShutup() != 4 {
		t.Fatalf("accept ChildrenShutup=%d", accept.ChildrenShutup())
	}

	nofork := NewDeferredNoFork("nofork", addrconfig.Address{})
	nofork.SetChildrenShutup(5)
	if nofork.ChildrenShutup() != 0 {
		t.Fatalf("nofork ChildrenShutup=%d", nofork.ChildrenShutup())
	}
}

func TestConstructorsRejectMissingResources(t *testing.T) {
	if o, err := NewReady("ready", nil); !errors.Is(err, errReadyRequiresStream) || o != nil {
		t.Fatalf("NewReady(nil) o=%v err=%v", o, err)
	}
	if o, err := NewReadySplit("split", nil, relay.FDStream{}); !errors.Is(err, errReadySplitRequiresIO) || o != nil {
		t.Fatalf("NewReadySplit(nil, write) o=%v err=%v", o, err)
	}
	if o, err := NewAcceptParent("accept", AcceptParent{}); !errors.Is(err, errAcceptRequiresListener) || o != nil {
		t.Fatalf("NewAcceptParent(nil listener) o=%v err=%v", o, err)
	}
	if o, err := NewRepeatedDial("dial", RepeatedDial{}); !errors.Is(err, errRepeatRequiresDialer) || o != nil {
		t.Fatalf("NewRepeatedDial(nil dialer) o=%v err=%v", o, err)
	}
}
