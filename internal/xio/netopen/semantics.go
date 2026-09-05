package netopen

import "github.com/oittaa/socat/internal/relay"

func (*udpDatagramConn) IOSemantics() relay.IOSemantics   { return relay.MessageIO }
func (*udpFilteredRecv) IOSemantics() relay.IOSemantics   { return relay.MessageIO }
func (*udpSessionConn) IOSemantics() relay.IOSemantics    { return relay.MessageIO }
func (*udpRecvFromConn) IOSemantics() relay.IOSemantics   { return relay.MessageIO }
func (*unixRecvStream) IOSemantics() relay.IOSemantics    { return relay.MessageIO }
func (*unixgramConn) IOSemantics() relay.IOSemantics      { return relay.MessageIO }
func (*rawIPDatagramConn) IOSemantics() relay.IOSemantics { return relay.MessageIO }
func (*rawIPConn) IOSemantics() relay.IOSemantics         { return relay.MessageIO }
func (*rawIPRecvFrom) IOSemantics() relay.IOSemantics     { return relay.MessageIO }
func (*rawIPFilteredRecv) IOSemantics() relay.IOSemantics { return relay.MessageIO }
func (*rawIPSessionConn) IOSemantics() relay.IOSemantics  { return relay.MessageIO }
