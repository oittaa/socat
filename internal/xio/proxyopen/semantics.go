package proxyopen

import "github.com/oittaa/socat/internal/relay"

func (*pipeConn) IOSemantics() relay.IOSemantics   { return relay.ByteStreamIO }
func (*prefixConn) IOSemantics() relay.IOSemantics { return relay.ByteStreamIO }
