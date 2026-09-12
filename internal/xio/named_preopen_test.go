package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
)

func TestNamedFilesystemUnixSocketUsesKindAndRole(t *testing.T) {
	listen := addrconfig.Address{
		Facts:   addrconfig.Facts{Kind: addrconfig.AddressKindUNIX, Role: addrconfig.AddressRoleListen},
		Network: addrconfig.Network{SocketPath: "/tmp/sock"},
	}
	if FDSkipNamedUnixSocket(listen) != FDSkipOwner {
		t.Fatal("UNIX listen filesystem name")
	}
	abstract := listen
	abstract.Network.SocketPath = "@abs"
	if FDSkipNamedUnixSocket(abstract) != (FDSkip{}) {
		t.Fatal("abstract UNIX listen")
	}
	byType := addrconfig.Address{Type: "UNIX-LISTEN"}
	if FDSkipNamedUnixSocket(byType) != (FDSkip{}) {
		t.Fatal("Type string without Kind/Role must not match")
	}
}
