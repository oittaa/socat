package posixmqopen

import "github.com/oittaa/socat/internal/xio"

const groupPOSIXMQ = "POSIX message queues (Linux)"

func init() {
	mqEnabled := func() bool { return xio.FeaturePOSIXMQ }

	xio.RegisterAddress(xio.AddressDesc{Group: groupPOSIXMQ, Name: "POSIXMQ", Syntax: "POSIXMQ:<mqname>", Desc: "POSIX message queue (bidirectional)", Enabled: mqEnabled, Opener: openPOSIXMQ})
	xio.RegisterAddress(xio.AddressDesc{Group: groupPOSIXMQ, Name: "POSIXMQ-BIDIRECTIONAL", Syntax: "POSIXMQ-BIDIRECTIONAL:<mqname>", Desc: "same as POSIXMQ", Enabled: mqEnabled, Opener: openPOSIXMQ})
	xio.RegisterAddress(xio.AddressDesc{Group: groupPOSIXMQ, Name: "POSIXMQ-READ", Syntax: "POSIXMQ-READ:<mqname>", Desc: "read a POSIX message queue", Enabled: mqEnabled, Opener: openPOSIXMQ})
	xio.RegisterAddress(xio.AddressDesc{Group: groupPOSIXMQ, Name: "POSIXMQ-RECEIVE", Syntax: "POSIXMQ-RECEIVE:<mqname>", Desc: "same as POSIXMQ-RECV", Enabled: mqEnabled, Opener: openPOSIXMQ})
	xio.RegisterAddress(xio.AddressDesc{Group: groupPOSIXMQ, Name: "POSIXMQ-RECV", Syntax: "POSIXMQ-RECV:<mqname>", Desc: "receive from a POSIX message queue", Enabled: mqEnabled, Opener: openPOSIXMQ})
	xio.RegisterAddress(xio.AddressDesc{Group: groupPOSIXMQ, Name: "POSIXMQ-SEND", Syntax: "POSIXMQ-SEND:<mqname>", Desc: "send to a POSIX message queue", Enabled: mqEnabled, Opener: openPOSIXMQ})
	xio.RegisterAddress(xio.AddressDesc{Group: groupPOSIXMQ, Name: "POSIXMQ-WRITE", Syntax: "POSIXMQ-WRITE:<mqname>", Desc: "same as POSIXMQ-SEND", Enabled: mqEnabled, Opener: openPOSIXMQ})
}
