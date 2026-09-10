package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/optionmeta"
)

func TestAncillaryCanonicalsMatchMatrix(t *testing.T) {
	want := make(map[string]struct{}, len(ipAncillaryMatrix))
	for _, e := range ipAncillaryMatrix {
		want[e.Canonical] = struct{}{}
	}
	for _, name := range optionmeta.AncillaryCanonicals() {
		if _, ok := want[name]; !ok {
			t.Errorf("catalog ancillary %q is not in the runtime matrix", name)
			continue
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("matrix row %q is not marked ancillary in optionmeta", name)
	}
}
