package relay

// IOSemantics describes whether an endpoint carries bytes or messages.
type IOSemantics uint8

const (
	UnknownIO IOSemantics = iota
	ByteStreamIO
	MessageIO
)

// ConfigureStreamPair selects optional endpoint adaptation before transfer.
// Each direction uses the opposite endpoint's corresponding I/O half.
func ConfigureStreamPair(left, right Stream) bool {
	lr, lw := StreamReadSemantics(left), StreamWriteSemantics(left)
	rr, rw := StreamReadSemantics(right), StreamWriteSemantics(right)
	a := configureRead(left, rw)
	b := configureWrite(left, rr)
	c := configureRead(right, lw)
	d := configureWrite(right, lr)
	return a || b || c || d
}

func configureRead(s Stream, peer IOSemantics) bool {
	if cfg := PropsOf(s).ConfigureRead; cfg != nil {
		cfg(peer)
		return true
	}
	return false
}

func configureWrite(s Stream, peer IOSemantics) bool {
	if cfg := PropsOf(s).ConfigureWrite; cfg != nil {
		cfg(peer)
		return true
	}
	return false
}

func StreamReadSemantics(s Stream) IOSemantics  { return PropsOf(s).ReadIO }
func StreamWriteSemantics(s Stream) IOSemantics { return PropsOf(s).WriteIO }
