package xio_test

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
)

func TestConstructorsRejectMissingResources(t *testing.T) {
	o, err := xio.NewReady("ready", nil)
	if o != nil || err == nil || !strings.Contains(err.Error(), "requires a stream") {
		t.Fatalf("NewReady(nil) o=%v err=%v", o, err)
	}

	o, err = xio.NewReadySplit("split", nil, relay.FDStream{})
	if o != nil || err == nil || !strings.Contains(err.Error(), "requires read and write") {
		t.Fatalf("NewReadySplit(nil, write) o=%v err=%v", o, err)
	}
	o, err = xio.NewReadySplit("split", relay.FDStream{}, nil)
	if o != nil || err == nil || !strings.Contains(err.Error(), "requires read and write") {
		t.Fatalf("NewReadySplit(read, nil) o=%v err=%v", o, err)
	}

	o, err = xio.NewAcceptParent("accept", xio.AcceptParent{})
	if o != nil || err == nil || !strings.Contains(err.Error(), "requires a listener") {
		t.Fatalf("NewAcceptParent(nil listener) o=%v err=%v", o, err)
	}

	o, err = xio.NewRepeatedDial("dial", xio.RepeatedDial{})
	if o != nil || err == nil || !strings.Contains(err.Error(), "requires a dialer") {
		t.Fatalf("NewRepeatedDial(nil dialer) o=%v err=%v", o, err)
	}
}

func TestOpenedKindIsDerivedFromPayload(t *testing.T) {
	ready, err := xio.NewReady("ready", relay.FDStream{})
	if err != nil {
		t.Fatal(err)
	}
	if ready.Kind() != xio.KindReady {
		t.Fatalf("ready Kind=%v", ready.Kind())
	}

	split, err := xio.NewReadySplit("split", relay.FDStream{}, relay.FDStream{})
	if err != nil {
		t.Fatal(err)
	}
	if split.Kind() != xio.KindReady {
		t.Fatalf("split Kind=%v", split.Kind())
	}
	if split.Stream() == nil || split.EffectiveStream() == nil {
		t.Fatal("split ready has no stream")
	}
}
