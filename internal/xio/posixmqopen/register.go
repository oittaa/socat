package posixmqopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	xio.Register("POSIXMQ", openPOSIXMQ)
	xio.Register("POSIXMQ-BIDIRECTIONAL", openPOSIXMQ)
	xio.Register("POSIXMQ-READ", openPOSIXMQ)
	xio.Register("POSIXMQ-RECEIVE", openPOSIXMQ)
	xio.Register("POSIXMQ-RECV", openPOSIXMQ)
	xio.Register("POSIXMQ-SEND", openPOSIXMQ)
	xio.Register("POSIXMQ-WRITE", openPOSIXMQ)
}
