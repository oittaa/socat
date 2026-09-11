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

func (c *udpDatagramConn) StreamProps() relay.Props   { return relay.Inspect(c) }
func (c *udpFilteredRecv) StreamProps() relay.Props   { return relay.Inspect(c) }
func (c *udpSessionConn) StreamProps() relay.Props    { return relay.Inspect(c) }
func (c *udpRecvFromConn) StreamProps() relay.Props   { return relay.Inspect(c) }
func (c *unixRecvStream) StreamProps() relay.Props    { return relay.Inspect(c) }
func (c *unixgramConn) StreamProps() relay.Props      { return relay.Inspect(c) }
func (c *rawIPDatagramConn) StreamProps() relay.Props { return relay.Inspect(c) }
func (c *rawIPConn) StreamProps() relay.Props         { return relay.Inspect(c) }
func (c *rawIPRecvFrom) StreamProps() relay.Props     { return relay.Inspect(c) }
func (c *rawIPFilteredRecv) StreamProps() relay.Props { return relay.Inspect(c) }
func (c *rawIPSessionConn) StreamProps() relay.Props  { return relay.Inspect(c) }
