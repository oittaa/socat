package dtlsopen

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/oittaa/socat/internal/dtls13"
	"github.com/oittaa/socat/internal/relay"
)

type datagramConn interface {
	net.Conn
	MaxDatagramSize() int
	CloseWrite() error
}

// streamConn adapts only the directions paired with byte streams.
type streamConn struct {
	datagramConn
	readStream, writeStream atomic.Bool
	readMu, writeMu         sync.Mutex
	buffer                  []byte
	remainder               []byte
}

func (*streamConn) IOSemantics() relay.IOSemantics { return relay.MessageIO }

func (c *streamConn) UnwrapStream() relay.Stream { return relay.NetStream{Conn: c.datagramConn} }

func (c *streamConn) ConfigureReadPeer(kind relay.IOSemantics) {
	c.readStream.Store(kind == relay.ByteStreamIO)
}

func (c *streamConn) ConfigureWritePeer(kind relay.IOSemantics) {
	c.writeStream.Store(kind == relay.ByteStreamIO)
}

func (c *streamConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if !c.readStream.Load() {
		return c.datagramConn.Read(p)
	}
	if len(c.remainder) == 0 {
		if c.buffer == nil {
			c.buffer = make([]byte, dtls13.MaxApplicationData)
		}
		n, err := c.datagramConn.Read(c.buffer)
		if err != nil {
			return 0, err
		}
		c.remainder = c.buffer[:n]
	}
	n := copy(p, c.remainder)
	c.remainder = c.remainder[n:]
	return n, nil
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if !c.writeStream.Load() || len(p) == 0 {
		return c.datagramConn.Write(p)
	}
	written := 0
	for written < len(p) {
		size := min(len(p)-written, c.MaxDatagramSize())
		for {
			if size <= 0 {
				return written, dtls13.ErrDatagramTooLarge
			}
			n, err := c.datagramConn.Write(p[written : written+size])
			written += n
			if n == 0 && errors.Is(err, dtls13.ErrDatagramTooLarge) {
				// Retry only a pre-send rejection at a strictly smaller limit.
				if limit := c.MaxDatagramSize(); limit > 0 && limit < size {
					size = limit
					continue
				}
			}
			if err != nil {
				return written, err
			}
			if n != size {
				return written, io.ErrShortWrite
			}
			break
		}
	}
	return written, nil
}

func (c *streamConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.datagramConn.CloseWrite()
}
