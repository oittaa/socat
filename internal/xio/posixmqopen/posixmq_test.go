package posixmqopen

import (
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
)

func TestKindOfUsesPreparedRole(t *testing.T) {
	if kindOf(addrconfig.Address{Type: "POSIXMQ-READ"}) != mqBidir {
		t.Fatal("Type string without Role must not select READ")
	}
	if kindOf(addrconfig.Address{Facts: addrconfig.Facts{Role: addrconfig.AddressRoleReceive}}) != mqRead {
		t.Fatal("READ")
	}
	if kindOf(addrconfig.Address{Facts: addrconfig.Facts{Role: addrconfig.AddressRoleReceiveFrom}}) != mqRecv {
		t.Fatal("RECV")
	}
	if kindOf(addrconfig.Address{Facts: addrconfig.Facts{Role: addrconfig.AddressRoleSendTo}}) != mqSend {
		t.Fatal("SEND")
	}
	if kindOf(addrconfig.Address{Facts: addrconfig.Facts{Role: addrconfig.AddressRoleDatagram}}) != mqBidir {
		t.Fatal("BIDIRECTIONAL")
	}
}
