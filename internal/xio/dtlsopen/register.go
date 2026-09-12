package dtlsopen

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

func init() {
	const (
		kind   = addrconfig.AddressKindDTLS
		anyIP  = addrconfig.IPFamilyAny
		client = addrconfig.AddressRoleConnect
		server = addrconfig.AddressRoleListen
	)
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupDTLS, Name: "OPENSSL-DTLS-CLIENT", Syntax: "OPENSSL-DTLS-CLIENT:<host>:<port>", Desc: "DTLS 1.3 datagram client", Opener: openClient, OptionCaps: xio.CapsSecureUDPConnect, Aliases: []string{"DTLS", "DTLS-C", "DTLS-CLIENT", "DTLS-CONNECT", "OPENSSL-DTLS-CONNECT"}, Kind: kind, Role: client, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupDTLS, Name: "OPENSSL-DTLS-SERVER", Syntax: "OPENSSL-DTLS-SERVER:<port>", Desc: "DTLS 1.3 datagram server; requires cert=", Opener: openServer, OptionCaps: xio.CapsSecureUDPListen, Aliases: []string{"DTLS-L", "DTLS-LISTEN", "DTLS-SERVER", "OPENSSL-DTLS-LISTEN"}, Kind: kind, Role: server, Family: anyIP})
}
