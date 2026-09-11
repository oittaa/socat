package relay

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// Props are the relay-visible capabilities of a Stream. Concrete endpoints
// fill them from the underlying conn or file. Wrappers that convert bytes
// (crnl, escape, timeouts, ignoreeof) clear zero-copy; transparent wrappers
// such as end-close copy the inner props as-is via Stream embedding.
type Props struct {
	ReadFD, WriteFD  int // -1 if this half has no descriptor
	SetReadDeadline  func(time.Time) error
	SetWriteDeadline func(time.Time) error
	NeedsPoll        bool
	ReadIO, WriteIO  IOSemantics
	ZeroCopyRead     syscall.Conn
	ZeroCopyWrite    syscall.Conn
	ConfigureRead    func(IOSemantics)
	ConfigureWrite   func(IOSemantics)
}

// NoProps is StreamProps for a stream with no relay-visible capabilities.
func NoProps() Props {
	return Props{ReadFD: -1, WriteFD: -1}
}

// WithoutZeroCopy clears kernel-copy endpoints so conversion wrappers cannot
// be bypassed by splice.
func WithoutZeroCopy(p Props) Props {
	p.ZeroCopyRead = nil
	p.ZeroCopyWrite = nil
	return p
}

func (s NetStream) StreamProps() Props { return Inspect(s.Conn) }

func (s RWCStream) StreamProps() Props { return Inspect(s.ReadWriteCloser) }

func (s FDStream) StreamProps() Props {
	rfd, rdl, rpoll, rio, rzc, rcfg := halfProps(s.R, true)
	wfd, wdl, wpoll, wio, wzc, wcfg := halfProps(s.W, false)
	return Props{
		ReadFD:           rfd,
		WriteFD:          wfd,
		SetReadDeadline:  rdl,
		SetWriteDeadline: wdl,
		NeedsPoll:        rpoll || wpoll,
		ReadIO:           rio,
		WriteIO:          wio,
		ZeroCopyRead:     rzc,
		ZeroCopyWrite:    wzc,
		ConfigureRead:    rcfg,
		ConfigureWrite:   wcfg,
	}
}

// PropsOf returns s.StreamProps, or NoProps if s is nil.
func PropsOf(s Stream) Props {
	if s == nil {
		return NoProps()
	}
	return s.StreamProps()
}

// Inspect reports the capabilities of one value without unwrapping wrappers.
// Leaf streams and test fakes use it as StreamProps.
func Inspect(v any) Props {
	p := NoProps()
	if v == nil {
		return p
	}
	if c, ok := v.(interface{ IOSemantics() IOSemantics }); ok {
		p.ReadIO, p.WriteIO = c.IOSemantics(), c.IOSemantics()
	} else {
		ioKind := inferIO(v)
		p.ReadIO, p.WriteIO = ioKind, ioKind
	}
	if c, ok := v.(interface{ ConfigureReadPeer(IOSemantics) }); ok {
		p.ConfigureRead = c.ConfigureReadPeer
	}
	if c, ok := v.(interface{ ConfigureWritePeer(IOSemantics) }); ok {
		p.ConfigureWrite = c.ConfigureWritePeer
	}
	if d, ok := v.(interface{ SetReadDeadline(time.Time) error }); ok {
		p.SetReadDeadline = d.SetReadDeadline
	}
	if d, ok := v.(interface{ SetWriteDeadline(time.Time) error }); ok {
		p.SetWriteDeadline = d.SetWriteDeadline
	}
	fd := streamValueFD(v)
	p.ReadFD, p.WriteFD = fd, fd
	p.NeedsPoll = valueNeedsPoll(v)
	if zc, ok := zeroCopyEndpoint(v); ok {
		p.ZeroCopyRead, p.ZeroCopyWrite = zc, zc
	}
	return p
}

func inferIO(v any) IOSemantics {
	switch c := v.(type) {
	case *tls.Conn, *net.TCPConn, *io.PipeReader, *io.PipeWriter, *bytes.Reader, *bytes.Buffer, *strings.Reader:
		return ByteStreamIO
	case *net.UDPConn, *net.IPConn:
		return MessageIO
	case *os.File:
		if st, err := c.Stat(); err == nil && (st.Mode().IsRegular() || st.Mode()&os.ModeNamedPipe != 0) {
			return ByteStreamIO
		}
		return descriptorSemantics(c)
	case syscall.Conn:
		return descriptorSemantics(c)
	default:
		return UnknownIO
	}
}

func valueNeedsPoll(v any) bool {
	if file, ok := v.(*os.File); ok {
		info, err := file.Stat()
		return err != nil || !info.Mode().IsRegular()
	}
	_, ok := v.(fdProvider)
	return ok
}

func zeroCopyEndpoint(v any) (syscall.Conn, bool) {
	switch endpoint := v.(type) {
	case *net.TCPConn:
		return endpoint, true
	case *net.UnixConn:
		return endpoint, true
	case *os.File:
		return endpoint, true
	default:
		return nil, false
	}
}

func halfProps(v any, read bool) (fd int, setDL func(time.Time) error, poll bool, ioKind IOSemantics, zc syscall.Conn, cfg func(IOSemantics)) {
	if v == nil {
		return -1, nil, false, UnknownIO, nil, nil
	}
	if st, ok := v.(Stream); ok {
		p := st.StreamProps()
		if read {
			return p.ReadFD, p.SetReadDeadline, p.NeedsPoll, p.ReadIO, p.ZeroCopyRead, p.ConfigureRead
		}
		return p.WriteFD, p.SetWriteDeadline, p.NeedsPoll, p.WriteIO, p.ZeroCopyWrite, p.ConfigureWrite
	}
	p := Inspect(v)
	fd, setDL, poll, ioKind, zc, cfg = p.ReadFD, p.SetReadDeadline, p.NeedsPoll, p.ReadIO, p.ZeroCopyRead, p.ConfigureRead
	if !read {
		fd, setDL, poll, ioKind, zc, cfg = p.WriteFD, p.SetWriteDeadline, p.NeedsPoll, p.WriteIO, p.ZeroCopyWrite, p.ConfigureWrite
	}
	if ioKind == UnknownIO || cfg == nil {
		semIO, semCfg := semanticHalf(v, read)
		if ioKind == UnknownIO {
			ioKind = semIO
		}
		if cfg == nil {
			cfg = semCfg
		}
	}
	return fd, setDL, poll, ioKind, zc, cfg
}

func semanticHalf(v any, read bool) (IOSemantics, func(IOSemantics)) {
	for range 32 {
		if v == nil {
			return UnknownIO, nil
		}
		if st, ok := v.(Stream); ok {
			p := st.StreamProps()
			if read {
				return p.ReadIO, p.ConfigureRead
			}
			return p.WriteIO, p.ConfigureWrite
		}
		if c, ok := v.(interface{ IOSemantics() IOSemantics }); ok {
			var cfg func(IOSemantics)
			if read {
				if x, ok := v.(interface{ ConfigureReadPeer(IOSemantics) }); ok {
					cfg = x.ConfigureReadPeer
				}
			} else if x, ok := v.(interface{ ConfigureWritePeer(IOSemantics) }); ok {
				cfg = x.ConfigureWritePeer
			}
			return c.IOSemantics(), cfg
		}
		if read {
			if u, ok := v.(interface{ UnwrapReader() io.Reader }); ok {
				v = u.UnwrapReader()
				continue
			}
		} else if u, ok := v.(interface{ UnwrapWriter() io.Writer }); ok {
			v = u.UnwrapWriter()
			continue
		}
		if c, ok := v.(interface{ NetConn() net.Conn }); ok {
			next := c.NetConn()
			if next == nil || next == v {
				break
			}
			v = next
			continue
		}
		p := Inspect(v)
		if read {
			return p.ReadIO, p.ConfigureRead
		}
		return p.WriteIO, p.ConfigureWrite
	}
	return UnknownIO, nil
}
