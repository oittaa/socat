package xio

import (
	"strconv"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func decodeUDP(t *testing.T, raw string) addrconfig.Address {
	t.Helper()
	s, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(s, addrconfig.Facts{Type: s.Type})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func multicastTestIface(req addrconfig.MulticastRequest) string {
	if req.InterfaceIsID {
		return strconv.FormatUint(uint64(req.InterfaceID), 10)
	}
	return req.InterfaceName
}

type testMembershipJoin struct {
	kind addrconfig.MulticastKind
	spec string
	name string
}

func membershipJoins(config addrconfig.Address) []testMembershipJoin {
	var out []testMembershipJoin
	for _, action := range config.Network.Actions {
		if action.Kind != addrconfig.SocketActionMulticast {
			continue
		}
		req := action.Multicast
		switch req.Kind {
		case addrconfig.MulticastJoinIPv4, addrconfig.MulticastJoinIPv6:
		default:
			continue
		}
		out = append(out, testMembershipJoin{
			kind: req.Kind,
			spec: req.Group.String() + ":" + multicastTestIface(req),
			name: req.Name,
		})
	}
	return out
}

func TestMembershipJoinsCollectsAllInOptionOrder(t *testing.T) {
	got := membershipJoins(decodeUDP(t, "UDP6-RECV:1,ip-add-membership=224.0.0.1:lo,ipv6-join-group=[ff02::2]:eth0"))
	if len(got) != 2 {
		t.Fatalf("mixed joins=%+v", got)
	}
	if got[0].kind != addrconfig.MulticastJoinIPv4 || got[0].name != "ip-add-membership" || got[0].spec != "224.0.0.1:lo" {
		t.Fatalf("ipv4 join=%+v", got[0])
	}
	if got[1].kind != addrconfig.MulticastJoinIPv6 || got[1].name != "ipv6-join-group" || got[1].spec != "ff02::2:eth0" {
		t.Fatalf("ipv6 join=%+v", got[1])
	}
}

func TestMembershipJoinsCollectsRepeatedOptions(t *testing.T) {
	got := membershipJoins(decodeUDP(t, "UDP6-RECV:1,ipv6-join-group=[ff02::2]:lo,ipv6-join-group=[ff02::3]:eth0"))
	if len(got) != 2 {
		t.Fatalf("repeated joins=%+v", got)
	}
	if got[0].spec != "ff02::2:lo" || got[1].spec != "ff02::3:eth0" {
		t.Fatalf("repeated order=%+v", got)
	}
	if got[0].kind != addrconfig.MulticastJoinIPv6 || got[1].kind != addrconfig.MulticastJoinIPv6 {
		t.Fatalf("repeated family=%+v", got)
	}
}

func TestMembershipJoinsRecognizesClassicAliases(t *testing.T) {
	got := membershipJoins(decodeUDP(t, "UDP6-RECV:1,join-group=[ff02::2]:lo,add-membership=224.0.0.1:lo,membership=224.0.0.2:eth0,ipv6-add-membership=[ff02::3]:eth1"))
	wantKind := []addrconfig.MulticastKind{addrconfig.MulticastJoinIPv6, addrconfig.MulticastJoinIPv4, addrconfig.MulticastJoinIPv4, addrconfig.MulticastJoinIPv6}
	wantSpec := []string{"ff02::2:lo", "224.0.0.1:lo", "224.0.0.2:eth0", "ff02::3:eth1"}
	wantName := []string{"ipv6-join-group", "ip-add-membership", "ip-add-membership", "ipv6-join-group"}
	if len(got) != 4 {
		t.Fatalf("alias joins=%+v", got)
	}
	for i := range wantKind {
		if got[i].kind != wantKind[i] || got[i].spec != wantSpec[i] || got[i].name != wantName[i] {
			t.Fatalf("alias[%d]=%+v want kind=%v spec=%q name=%q", i, got[i], wantKind[i], wantSpec[i], wantName[i])
		}
	}
}

func TestMembershipFamilyIgnoresAddressWhenClassifying(t *testing.T) {
	got := membershipJoins(decodeUDP(t, "UDP6-RECV:1,ip-add-membership=[ff02::2]:lo"))
	if len(got) != 1 || got[0].kind != addrconfig.MulticastJoinIPv4 {
		t.Fatalf("ip-add-membership must stay IPv4 sockopt family, got %+v", got)
	}

	got = membershipJoins(decodeUDP(t, "UDP6-RECV:1,ipv6-join-group=224.0.0.1:lo"))
	if len(got) != 1 || got[0].kind != addrconfig.MulticastJoinIPv6 {
		t.Fatalf("ipv6-join-group must stay IPv6 sockopt family, got %+v", got)
	}
}

func TestMulticastNamedAliases(t *testing.T) {
	config := decodeUDP(t, "UDP4:localhost:1,mcloop=0,multicast-ttl=9,multicast-if=127.0.0.1,mcloop6=1")
	got := map[addrconfig.MulticastKind]addrconfig.MulticastRequest{}
	for _, action := range config.Network.Actions {
		if action.Kind != addrconfig.SocketActionMulticast {
			continue
		}
		got[action.Multicast.Kind] = action.Multicast
	}
	if req, ok := got[addrconfig.MulticastLoopIPv4]; !ok || req.Name != "ip-multicast-loop" || req.Value != 0 {
		t.Fatalf("loop=%+v ok=%v", req, ok)
	}
	if req, ok := got[addrconfig.MulticastTTLIPv4]; !ok || req.Name != "ip-multicast-ttl" || req.Value != 9 {
		t.Fatalf("ttl=%+v ok=%v", req, ok)
	}
	if req, ok := got[addrconfig.MulticastInterfaceIPv4]; !ok || req.Name != "ip-multicast-if" || req.InterfaceAddr.String() != "127.0.0.1" {
		t.Fatalf("if=%+v ok=%v", req, ok)
	}
	if req, ok := got[addrconfig.MulticastLoopIPv6]; !ok || req.Name != "ipv6-multicast-loop" || req.Value != 1 {
		t.Fatalf("mcloop6=%+v ok=%v", req, ok)
	}
}

func TestMTUDiscoveryAliases(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		name string
	}{
		{raw: "UDP:127.0.0.1:1,ip-mtu-discover=1", name: "ip-mtu-discover"},
		{raw: "UDP:127.0.0.1:1,mtudiscover=1", name: "ip-mtu-discover"},
		{raw: "UDP:127.0.0.1:1,ipmtudiscover=1", name: "ip-mtu-discover"},
		{raw: "UDP6:[::1]:1,ipv6-mtu-discover=1", name: "ipv6-mtu-discover"},
		{raw: "UDP6:[::1]:1,mtudiscover6=1", name: "ipv6-mtu-discover"},
	} {
		config := decodeUDP(t, tc.raw)
		var got string
		for _, action := range config.Network.Actions {
			if action.Kind == addrconfig.SocketActionMTUDiscovery {
				got = action.Text
			}
		}
		if got != tc.name {
			t.Errorf("%s: MTU discovery name=%q want %q", tc.raw, got, tc.name)
		}
	}
}
