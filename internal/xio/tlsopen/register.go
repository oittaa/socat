package tlsopen

import "github.com/oittaa/socat/internal/xio"

const groupTLS = "TLS (OPENSSL/SSL aliases)"

func init() {
	// Canonical names.
	xio.RegisterAddress(xio.AddressDesc{Group: groupTLS, Name: "TLS", Syntax: "TLS:<host>:<port>", Desc: "TLS client (stream TLS, not DTLS)", Opener: openTLSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupTLS, Name: "TLS-CONNECT", Syntax: "TLS-CONNECT:<host>:<port>", Desc: "same as TLS", Opener: openTLSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupTLS, Name: "TLS-LISTEN", Syntax: "TLS-LISTEN:<port>", Desc: "TLS server; requires cert=", Opener: openTLSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: groupTLS, Name: "TLS-L", Syntax: "TLS-L:<port>", Desc: "same as TLS-LISTEN", Opener: openTLSListen})

	// Classic drop-in aliases (test.sh and existing scripts).
	xio.RegisterAddress(xio.AddressDesc{Group: groupTLS, Name: "OPENSSL", Syntax: "OPENSSL:<host>:<port>", Desc: "alias of TLS", Opener: openTLSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupTLS, Name: "OPENSSL-CONNECT", Syntax: "OPENSSL-CONNECT:<host>:<port>", Desc: "alias of TLS-CONNECT", Opener: openTLSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupTLS, Name: "OPENSSL-LISTEN", Syntax: "OPENSSL-LISTEN:<port>", Desc: "alias of TLS-LISTEN", Opener: openTLSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: groupTLS, Name: "OPENSSL-L", Syntax: "OPENSSL-L:<port>", Desc: "alias of TLS-L", Opener: openTLSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: groupTLS, Name: "SSL", Syntax: "SSL:<host>:<port>", Desc: "alias of TLS", Opener: openTLSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupTLS, Name: "SSL-CONNECT", Syntax: "SSL-CONNECT:<host>:<port>", Desc: "alias of TLS-CONNECT", Opener: openTLSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupTLS, Name: "SSL-LISTEN", Syntax: "SSL-LISTEN:<port>", Desc: "alias of TLS-LISTEN", Opener: openTLSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: groupTLS, Name: "SSL-L", Syntax: "SSL-L:<port>", Desc: "alias of TLS-L", Opener: openTLSListen})
}
