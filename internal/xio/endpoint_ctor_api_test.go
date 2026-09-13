package xio_test

import (
	"testing"

	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
)

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
