package wsopen

import "github.com/oittaa/socat/internal/relay"

func (*wsNetConn) IOSemantics() relay.IOSemantics { return relay.ByteStreamIO }
