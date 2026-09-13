package xio

import (
	"errors"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/relay"
)

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
	if o, err := NewReadySplit("split", relay.FDStream{}, nil); !errors.Is(err, errReadySplitRequiresIO) || o != nil {
		t.Fatalf("NewReadySplit(read, nil) o=%v err=%v", o, err)
	}
	if o, err := NewAcceptParent("accept", AcceptParent{}); !errors.Is(err, errAcceptRequiresListener) || o != nil {
		t.Fatalf("NewAcceptParent(nil listener) o=%v err=%v", o, err)
	}
	if o, err := NewRepeatedDial("dial", RepeatedDial{}); !errors.Is(err, errRepeatRequiresDialer) || o != nil {
		t.Fatalf("NewRepeatedDial(nil dialer) o=%v err=%v", o, err)
	}
}
