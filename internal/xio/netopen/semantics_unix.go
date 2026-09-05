//go:build linux || darwin

package netopen

import "github.com/oittaa/socat/internal/relay"

func (*socketDgramStream) IOSemantics() relay.IOSemantics    { return relay.MessageIO }
func (*socketRecvfromStream) IOSemantics() relay.IOSemantics { return relay.MessageIO }
