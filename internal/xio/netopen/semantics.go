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
func (*oneshotForkConn) IOSemantics() relay.IOSemantics   { return relay.MessageIO }

func (u *udpDatagramConn) StreamProps() relay.Props   { return relay.Inspect(u) }
func (u *udpFilteredRecv) StreamProps() relay.Props   { return relay.Inspect(u) }
func (u *udpSessionConn) StreamProps() relay.Props    { return relay.Inspect(u) }
func (u *udpRecvFromConn) StreamProps() relay.Props   { return relay.Inspect(u) }
func (u *unixRecvStream) StreamProps() relay.Props    { return relay.Inspect(u) }
func (u *unixgramConn) StreamProps() relay.Props      { return relay.Inspect(u) }
func (r *rawIPDatagramConn) StreamProps() relay.Props { return relay.Inspect(r) }
func (r *rawIPConn) StreamProps() relay.Props         { return relay.Inspect(r) }
func (r *rawIPRecvFrom) StreamProps() relay.Props     { return relay.Inspect(r) }
func (r *rawIPFilteredRecv) StreamProps() relay.Props { return relay.Inspect(r) }
func (c *oneshotForkConn) StreamProps() relay.Props   { return relay.Inspect(c) }
