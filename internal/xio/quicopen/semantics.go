package quicopen

import "github.com/oittaa/socat/internal/relay"

func (*quicNetConn) IOSemantics() relay.IOSemantics { return relay.ByteStreamIO }
