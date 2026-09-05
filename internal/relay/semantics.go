package relay

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

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
	a := configurePeer(left, streamRead, rw)
	b := configurePeer(left, streamWrite, rr)
	c := configurePeer(right, streamRead, lw)
	d := configurePeer(right, streamWrite, lr)
	return a || b || c || d
}

func configurePeer(s Stream, direction streamDirection, peer IOSemantics) bool {
	return walkStreamCapabilities(s, func(value any) bool {
		if direction == streamRead {
			if c, ok := value.(interface{ ConfigureReadPeer(IOSemantics) }); ok {
				c.ConfigureReadPeer(peer)
				return true
			}
		} else if c, ok := value.(interface{ ConfigureWritePeer(IOSemantics) }); ok {
			c.ConfigureWritePeer(peer)
			return true
		}
		return false
	}, func(value any) []any { return semanticChildren(value, direction) })
}

func StreamReadSemantics(s Stream) IOSemantics  { return streamSemantics(s, streamRead) }
func StreamWriteSemantics(s Stream) IOSemantics { return streamSemantics(s, streamWrite) }

func streamSemantics(s Stream, direction streamDirection) IOSemantics {
	kind := UnknownIO
	walkStreamCapabilities(s, func(value any) bool {
		if c, ok := value.(interface{ IOSemantics() IOSemantics }); ok {
			kind = c.IOSemantics()
			return true
		}
		switch c := value.(type) {
		case *tls.Conn, *net.TCPConn, *io.PipeReader, *io.PipeWriter, *bytes.Reader, *bytes.Buffer, *strings.Reader:
			kind = ByteStreamIO
		case *net.UDPConn, *net.IPConn:
			kind = MessageIO
		case *os.File:
			if st, err := c.Stat(); err == nil && (st.Mode().IsRegular() || st.Mode()&os.ModeNamedPipe != 0) {
				kind = ByteStreamIO
			} else {
				kind = descriptorSemantics(c)
			}
		case syscall.Conn:
			kind = descriptorSemantics(c)
		}
		return kind != UnknownIO
	}, func(value any) []any { return semanticChildren(value, direction) })
	return kind
}

func semanticChildren(value any, direction streamDirection) []any {
	if direction == streamRead {
		if c, ok := value.(interface{ UnwrapReader() io.Reader }); ok {
			return []any{c.UnwrapReader()}
		}
	} else if c, ok := value.(interface{ UnwrapWriter() io.Writer }); ok {
		return []any{c.UnwrapWriter()}
	}
	if c, ok := value.(interface{ NetConn() net.Conn }); ok {
		return []any{c.NetConn()}
	}
	return regularStreamChildren(value, direction)
}
