package tlsopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	// Canonical names.
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTLS, Name: "TLS", Syntax: "TLS:<host>:<port>", Desc: "TLS client (stream TLS, not DTLS)", Opener: openTLSConnect, OptionCaps: xio.CapsTLSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTLS, Name: "TLS-CONNECT", Syntax: "TLS-CONNECT:<host>:<port>", Desc: "same as TLS", Opener: openTLSConnect, OptionCaps: xio.CapsTLSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTLS, Name: "TLS-LISTEN", Syntax: "TLS-LISTEN:<port>", Desc: "TLS server; requires cert=", Opener: openTLSListen, OptionCaps: xio.CapsTLSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTLS, Name: "TLS-L", Syntax: "TLS-L:<port>", Desc: "same as TLS-LISTEN", Opener: openTLSListen, OptionCaps: xio.CapsTLSListen})

	// OPENSSL/SSL names are aliases of TLS / TLS-CONNECT / TLS-LISTEN / TLS-L.
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTLS, Name: "OPENSSL", Syntax: "OPENSSL:<host>:<port>", Desc: "alias of TLS", Opener: openTLSConnect, OptionCaps: xio.CapsTLSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTLS, Name: "OPENSSL-CONNECT", Syntax: "OPENSSL-CONNECT:<host>:<port>", Desc: "alias of TLS-CONNECT", Opener: openTLSConnect, OptionCaps: xio.CapsTLSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTLS, Name: "OPENSSL-LISTEN", Syntax: "OPENSSL-LISTEN:<port>", Desc: "alias of TLS-LISTEN", Opener: openTLSListen, OptionCaps: xio.CapsTLSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTLS, Name: "OPENSSL-L", Syntax: "OPENSSL-L:<port>", Desc: "alias of TLS-L", Opener: openTLSListen, OptionCaps: xio.CapsTLSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTLS, Name: "SSL", Syntax: "SSL:<host>:<port>", Desc: "alias of TLS", Opener: openTLSConnect, OptionCaps: xio.CapsTLSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTLS, Name: "SSL-CONNECT", Syntax: "SSL-CONNECT:<host>:<port>", Desc: "alias of TLS-CONNECT", Opener: openTLSConnect, OptionCaps: xio.CapsTLSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTLS, Name: "SSL-LISTEN", Syntax: "SSL-LISTEN:<port>", Desc: "alias of TLS-LISTEN", Opener: openTLSListen, OptionCaps: xio.CapsTLSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTLS, Name: "SSL-L", Syntax: "SSL-L:<port>", Desc: "alias of TLS-L", Opener: openTLSListen, OptionCaps: xio.CapsTLSListen})
}
