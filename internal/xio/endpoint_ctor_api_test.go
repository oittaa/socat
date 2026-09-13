package xio_test

import (
	"testing"

	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
)

func TestNewReadySplitExposesStream(t *testing.T) {
	split, err := xio.NewReadySplit("split", relay.FDStream{}, relay.FDStream{})
	if err != nil {
		t.Fatal(err)
	}
	if split.Stream() == nil || split.EffectiveStream() == nil {
		t.Fatal("split ready has no stream")
	}
}
