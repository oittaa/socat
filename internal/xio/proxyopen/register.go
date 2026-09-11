package proxyopen

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

func init() {
	const (
		kindProxy = addrconfig.AddressKindPROXY
		kindSocks = addrconfig.AddressKindSOCKS
		connect   = addrconfig.AddressRoleConnect
		anyIP     = addrconfig.IPFamilyAny
	)
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupProxy, Name: "PROXY", Syntax: "PROXY:<proxy>:<host>:<port>", Desc: "HTTP CONNECT client", Opener: openProxyConnect, OptionCaps: xio.CapsProxy, Kind: kindProxy, Role: connect, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupProxy, Name: "PROXY-CONNECT", Syntax: "PROXY-CONNECT:<proxy>:<host>:<port>", Desc: "same as PROXY", Opener: openProxyConnect, OptionCaps: xio.CapsProxy, Kind: kindProxy, Role: connect, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupProxy, Name: "SOCKS4", Syntax: "SOCKS4:<socks>:<host>:<port>", Desc: "SOCKS4 client", Opener: openSOCKS4Connect, OptionCaps: xio.CapsSocks, Aliases: []string{"SOCKS"}, Kind: kindSocks, Role: connect, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupProxy, Name: "SOCKS4A", Syntax: "SOCKS4A:<socks>:<host>:<port>", Desc: "SOCKS4a client", Opener: openSOCKS4AConnect, OptionCaps: xio.CapsSocks, Kind: kindSocks, Role: connect, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupProxy, Name: "SOCKS5", Syntax: "SOCKS5:<socks>:<host>:<port>", Desc: "SOCKS5 client", Opener: openSOCKS5Connect, OptionCaps: xio.CapsSocks, Kind: kindSocks, Role: connect, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupProxy, Name: "SOCKS5-CONNECT", Syntax: "SOCKS5-CONNECT:<socks>:<host>:<port>", Desc: "same as SOCKS5", Opener: openSOCKS5Connect, OptionCaps: xio.CapsSocks, Kind: kindSocks, Role: connect, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupProxy, Name: "SOCKS5-LISTEN", Syntax: "SOCKS5-LISTEN:<socks>:<host>:<port>", Desc: "SOCKS5 BIND (remote listen)", Opener: openSOCKS5Listen, OptionCaps: xio.CapsSocks, Kind: kindSocks, Role: connect, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupProxy, Name: "SOCKS5-BIND", Syntax: "SOCKS5-BIND:<socks>:<host>:<port>", Desc: "same as SOCKS5-LISTEN", Opener: openSOCKS5Listen, OptionCaps: xio.CapsSocks, Kind: kindSocks, Role: connect, Family: anyIP})
}
