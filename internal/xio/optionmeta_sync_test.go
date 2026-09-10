package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/optionmeta"
)

func TestOptionMetaGroupConstantsMatch(t *testing.T) {
	pairs := [][2]string{
		{optionmeta.GroupTCP, GroupTCP},
		{optionmeta.GroupUDP, GroupUDP},
		{optionmeta.GroupRawIP, GroupRawIP},
		{optionmeta.GroupUnix, GroupUnix},
		{optionmeta.GroupSocket, GroupSocket},
		{optionmeta.GroupProcess, GroupProcess},
		{optionmeta.GroupDTLS, GroupDTLS},
		{optionmeta.GroupTLS, GroupTLS},
		{optionmeta.GroupProxy, GroupProxy},
		{optionmeta.GroupTUN, GroupTUN},
		{optionmeta.GroupWebSocket, GroupWebSocket},
		{optionmeta.GroupQUIC, GroupQUIC},
		{optionmeta.GroupSCTP, GroupSCTP},
		{optionmeta.GroupVSOCK, GroupVSOCK},
		{optionmeta.GroupPOSIXMQ, GroupPOSIXMQ},
		{optionmeta.GroupFiles, GroupFiles},
	}
	for _, pair := range pairs {
		if pair[0] != pair[1] {
			t.Errorf("optionmeta %q != xio %q", pair[0], pair[1])
		}
	}
}

func TestOptionMetaCapConstantsMatch(t *testing.T) {
	if optionmeta.CapSocket[0] != CapSocket || optionmeta.CapOpenSSL[0] != CapOpenSSL {
		t.Fatal("capability tokens drifted")
	}
}

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
