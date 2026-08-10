package endpoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// ErrAcceptTimeout is returned when accept-timeout expires with no connection.
// Classic socat exits 0 in this case (not an error for the process).
var ErrAcceptTimeout = errors.New("accept timeout")

// Mode indicates how an address is used.
type Mode int

const (
	ModeRDWR Mode = iota
	ModeRead
	ModeWrite
)

// IPVersion prefers a particular IP family for ambiguous addresses.
type IPVersion int

const (
	IPvDefault IPVersion = iota // classic -4 default since 1.8.0.1
	IPv4
	IPv6
	IPvAny // -0
)

// Global holds process-wide options affecting address open.
type Global struct {
	Log         *logx.Logger
	IPVersion   IPVersion
	BlockSize   int
	Linger      time.Duration
	Idle        time.Duration
	LeftToRight bool
	RightToLeft bool
	Verbose     bool
	Hex         bool
	Dump        io.Writer
	Statistics  bool
	Sloppy      bool // -s continue on some errors

	// Peer info from the most recently accepted/connected socket (for SOCAT_* env).
	SockAddr string
	PeerAddr string
	SockPort string
	PeerPort string

	// TLS peer certificate fields (classic SOCAT_OPENSSL_X509_*).
	TLSPeerSubject    string
	TLSPeerIssuer     string
	TLSPeerCommonName string
	TLSPeerCountry    string
	TLSPeerLocality   string
	TLSPeerOrg        string
	TLSPeerOrgUnit    string

	// Child process exit (EXEC/SYSTEM): non-zero promotes socat process exit.
	ChildExitCode int
	ChildErr      error

	// Classic -r / -R raw transfer dumps (left→right / right→left).
	// Path templates may contain $PROGNAME, $TIMESTAMP, $MICROS, $$, $ENV.
	// Files are opened at transfer start (after peer is known) with CLOEXEC.
	RawLeftPath  string
	RawRightPath string
	Progname     string // -lp value; default "socat"
	RawLeft      *os.File
	RawRight     *os.File
}

// Opened is a live address endpoint ready for transfer or accept-loop.
type Opened struct {
	Stream   relay.Stream
	Listener net.Listener // non-nil for listen without yet accepting (fork mode parent)
	// AcceptOne blocks until a connection is accepted (non-fork listen).
	// If set, Stream is nil until AcceptOne is used OR Open already accepted.
	// Fork: Listener set, Stream nil.
	// Non-fork listen: Stream is the accepted connection.
	Fork    bool
	Label   string
	cleanup []func()
	// PeerFilter rejects accepted connections (range/sourceport/lowport).
	// Used by fork accept loops; non-fork applies the same check before returning.
	PeerFilter func(net.Conn) error
	// MaxChildren limits concurrent fork children (0 = unlimited). Classic max-children.
	MaxChildren int
	// ConnectFork: client-side reconnect loop (TCP/OPENSSL/SOCKS/PROXY CONNECT with fork).
	// Parent dials repeatedly; each child transfers one connection. Dial must
	// complete the full open (including TLS/SOCKS/HTTP handshake).
	ConnectFork bool
	Dial        func(ctx context.Context) (net.Conn, error)
	// WrapDial wraps each dialed conn for transfer (crlf, escape, …). Optional.
	WrapDial func(net.Conn) (relay.Stream, error)
	// Interval between parent connect iterations (classic interval= seconds).
	Interval time.Duration
	// For dual: separate read/write streams
	Read  relay.Stream
	Write relay.Stream
	// NoForkSpec: EXEC/SYSTEM,nofork — process started in Run with peer FD as stdio.
	NoForkSpec *parse.Spec
}

// Close releases resources.
func (o *Opened) Close() error {
	var first error
	// Prefer cleanup hooks (they own the real FDs). Avoid comparing Stream
	// values: relay.FDStream holds funcs and is not comparable.
	if o.Stream != nil {
		if err := o.Stream.Close(); err != nil && first == nil {
			first = err
		}
		o.Stream = nil
	}
	if o.Listener != nil {
		if err := o.Listener.Close(); err != nil && first == nil {
			first = err
		}
		o.Listener = nil
	}
	for i := len(o.cleanup) - 1; i >= 0; i-- {
		o.cleanup[i]()
	}
	o.cleanup = nil
	o.Read = nil
	o.Write = nil
	return first
}

func (o *Opened) addCleanup(f func()) {
	o.cleanup = append(o.cleanup, f)
}

// EffectiveStream returns the stream used for bidirectional transfer.
func (o *Opened) EffectiveStream() relay.Stream {
	if o.Stream != nil {
		return o.Stream
	}
	if o.Read != nil || o.Write != nil {
		return relay.FDStream{
			R: readerOrEOF(o.Read),
			W: writerOrDiscard(o.Write),
			C: multiCloser{o.Read, o.Write},
			CloseW: func() error {
				if o.Write != nil {
					return o.Write.ShutdownWrite()
				}
				return nil
			},
		}
	}
	return nil
}

type multiCloser struct{ a, b relay.Stream }

func (m multiCloser) Close() error {
	var err error
	if m.a != nil {
		err = m.a.Close()
	}
	if m.b != nil {
		if e := m.b.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func readerOrEOF(s relay.Stream) io.Reader {
	if s != nil {
		return s
	}
	return eofReader{}
}

func writerOrDiscard(s relay.Stream) io.Writer {
	if s != nil {
		return s
	}
	return io.Discard
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

// OpenChannel opens a parsed address channel.
func OpenChannel(ctx context.Context, ch parse.Channel, mode Mode, g *Global) (*Opened, error) {
	if ch.IsDual() {
		return openDual(ctx, ch.Dual, g)
	}
	return OpenSpec(ctx, *ch.Single, mode, g)
}

func openDual(ctx context.Context, d *parse.Dual, g *Global) (*Opened, error) {
	left, err := OpenSpec(ctx, d.Left, ModeRead, g)
	if err != nil {
		return nil, fmt.Errorf("dual read side: %w", err)
	}
	right, err := OpenSpec(ctx, d.Right, ModeWrite, g)
	if err != nil {
		left.Close()
		return nil, fmt.Errorf("dual write side: %w", err)
	}
	o := &Opened{
		Read:  left.EffectiveStream(),
		Write: right.EffectiveStream(),
		Label: d.Raw,
	}
	o.addCleanup(func() { left.Close() })
	o.addCleanup(func() { right.Close() })
	// Combine into Stream
	o.Stream = relay.FDStream{
		R: o.Read,
		W: o.Write,
		C: multiCloser{o.Read, o.Write},
		CloseW: func() error {
			return o.Write.ShutdownWrite()
		},
	}
	return o, nil
}

// OpenSpec opens a single address type.
func OpenSpec(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	typ := normalizeType(s.Type)
	s.Type = typ
	openers := map[string]openerFunc{
		"STDIO":         openSTDIO,
		"STDIN":         openSTDIN,
		"STDOUT":        openSTDOUT,
		"STDERR":        openSTDERR,
		"FD":            openFD,
		"PIPE":          openPIPE,
		"FIFO":          openPIPE,
		"ECHO":          openPIPE, // classic synonym for unnamed/named pipe echo
		"OPEN":          openOPEN,
		"FILE":          openOPEN, // classic synonym
		"CREATE":        openCREATE,
		"CREAT":         openCREATE, // classic short form
		"GOPEN":         openGOPEN,
		"TCP":           openTCPConnect,
		"TCP4":          openTCP4Connect,
		"TCP6":          openTCP6Connect,
		"TCP-CONNECT":   openTCPConnect,
		"TCP4-CONNECT":  openTCP4Connect,
		"TCP6-CONNECT":  openTCP6Connect,
		"TCP-LISTEN":    openTCPListen,
		"TCP4-LISTEN":   openTCP4Listen,
		"TCP6-LISTEN":   openTCP6Listen,
		"TCP-L":         openTCPListen,
		"TCP4-L":        openTCP4Listen,
		"TCP6-L":        openTCP6Listen,
		"UDP":           openUDPConnect,
		"UDP4":          openUDP4Connect,
		"UDP6":          openUDP6Connect,
		"UDP-CONNECT":   openUDPConnect,
		"UDP4-CONNECT":  openUDP4Connect,
		"UDP6-CONNECT":  openUDP6Connect,
		"UDP-LISTEN":    openUDPListen,
		"UDP4-LISTEN":   openUDP4Listen,
		"UDP6-LISTEN":   openUDP6Listen,
		"UDP-L":         openUDPListen,
		"UDP4-L":        openUDP4Listen,
		"UDP6-L":        openUDP6Listen,
		"UDP-SENDTO":    openUDPSendto,
		"UDP4-SENDTO":   openUDP4Sendto,
		"UDP6-SENDTO":   openUDP6Sendto,
		"UDP-SEND":      openUDPSendto,
		"UDP4-SEND":     openUDP4Sendto,
		"UDP6-SEND":     openUDP6Sendto,
		"UDP-DATAGRAM":  openUDPDatagram,
		"UDP4-DATAGRAM": openUDP4Datagram,
		"UDP6-DATAGRAM": openUDP6Datagram,
		"UDP-RECV":      openUDPRecv,
		"UDP4-RECV":     openUDP4Recv,
		"UDP6-RECV":     openUDP6Recv,
		"UDP-RECVFROM":  openUDPRecvfrom,
		"UDP4-RECVFROM": openUDP4Recvfrom,
		"UDP6-RECVFROM": openUDP6Recvfrom,
		// Raw IP (SOCK_RAW; needs CAP_NET_RAW). Classic IP4/IP6-* tests.
		"IP":            openIP, // family from host (IP:127.0.0.1 vs IP:[::1])
		"IP4":           openIP4,
		"IP6":           openIP6,
		"IP-SENDTO":     openIPSendto,
		"IP4-SENDTO":    openIP4Sendto,
		"IP6-SENDTO":    openIP6Sendto,
		"IP-DATAGRAM":   openIPDatagram,
		"IP4-DATAGRAM":  openIP4Datagram,
		"IP6-DATAGRAM":  openIP6Datagram,
		"IP-RECV":       openIPRecv,
		"IP4-RECV":      openIP4Recv,
		"IP6-RECV":      openIP6Recv,
		"IP-RECVFROM":   openIPRecvfrom,
		"IP4-RECVFROM":  openIP4Recvfrom,
		"IP6-RECVFROM":  openIP6Recvfrom,
		"UNIX":          openUnixConnect,
		"UNIX-CONNECT":  openUnixConnect,
		"UNIX-CLIENT":   openUnixConnect,
		"UNIX-LISTEN":   openUnixListen,
		"UNIX-L":        openUnixListen,
		"UNIX-SENDTO":   openUnixSendto,
		"UNIX-RECVFROM": openUnixRecvfrom,
		"UNIX-RECV":     openUnixRecv,
		"UNIX-DATAGRAM": openUnixDatagram,
		// Linux abstract namespace.
		"ABSTRACT-LISTEN":   openAbstractListen,
		"ABSTRACT-L":        openAbstractListen,
		"ABSTRACT-CLIENT":   openAbstractConnect,
		"ABSTRACT-CONNECT":  openAbstractConnect,
		"ABSTRACT-SENDTO":   openAbstractSendto,
		"ABSTRACT-RECVFROM": openAbstractRecvfrom,
		"ABSTRACT-RECV":     openAbstractRecv,
		// HTTP CONNECT and SOCKS4/4A clients.
		"PROXY":           openProxyConnect,
		"PROXY-CONNECT":   openProxyConnect,
		"SOCKS4":          openSOCKS4Connect,
		"SOCKS4A":         openSOCKS4AConnect,
		"SOCKS5":          openSOCKS5Connect,
		"SOCKS5-CONNECT":  openSOCKS5Connect,
		"SOCKETPAIR":      openSocketpair,
		"SOCKET-CONNECT":  openSocketConnect,
		"SOCKET-LISTEN":   openSocketListen,
		"SOCKET-SENDTO":   openSocketSendto,
		"SOCKET-DATAGRAM": openSocketDatagram,
		"SOCKET-RECV":     openSocketRecv,
		"SOCKET-RECVFROM": openSocketRecvfrom,
		"EXEC":            openEXEC,
		"SYSTEM":          openSYSTEM,
		"SHELL":           openSHELL,
		"TEXT":            openTEXT,
		"STALL":           openSTALL,
		"PTY":             openPTY,
		// Stream TLS (crypto/tls). DTLS is not available in crypto/tls.
		"OPENSSL":         openTLSConnect,
		"OPENSSL-CONNECT": openTLSConnect,
		"SSL":             openTLSConnect,
		"SSL-CONNECT":     openTLSConnect,
		"OPENSSL-LISTEN":  openTLSListen,
		"OPENSSL-L":       openTLSListen,
		"SSL-LISTEN":      openTLSListen,
		"SSL-L":           openTLSListen,
		// Linux TUN/TAP and AF_PACKET INTERFACE (need CAP_NET_ADMIN).
		"TUN":       openTUN,
		"INTERFACE": openINTERFACE,
	}
	fn, ok := openers[typ]
	if !ok {
		// Message text must match classic for test.sh testaddrs():
		// grep "E unknown device/address"
		return nil, fmt.Errorf("unknown device/address \"%s\"", s.Type)
	}
	return fn(ctx, s, mode, g)
}

type openerFunc func(context.Context, parse.Spec, Mode, *Global) (*Opened, error)

func normalizeType(t string) string {
	t = strings.ToUpper(t)
	// synonyms already uppercased
	return t
}
