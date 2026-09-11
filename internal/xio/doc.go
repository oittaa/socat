// Package xio is the socat extended-I/O core: session state, stream helpers,
// peer filters, dial utilities, and Run orchestration.
//
// Address openers live in subpackages and register via Register (init):
//
//	netopen     - TCP, UDP, UNIX, SOCKET, raw IP
//	tlsopen     - TLS (OPENSSL/SSL aliases) via crypto/tls
//	dtlsopen    - DTLS 1.3 via internal/dtls13
//	proxyopen   - PROXY, SOCKS4/4A/5
//	fileopen    - STDIO, FILE, PIPE, PTY, TEXT, STALL
//	posixmqopen - POSIX message queues (Linux)
//	tunopen     - TUN, INTERFACE (Linux)
//	wsopen      - WS / WSS (coder/websocket)
//	quicopen    - QUIC (quic-go; not HTTP/3)
//
// EXEC/SYSTEM/SHELL stay in this package (tightly coupled to Run / nofork).
// Import internal/xio/all from main/cli so opener registration runs.
//
// OPENSSL/SSL type names and SOCAT_OPENSSL_X509_* env stay as aliases
// so existing scripts keep matching.
//
// # Opener lifecycle
//
// OpenSpec is the common entry. It looks up the registered opener, rewrites
// the type to the catalog name, ResolveChdirPaths, then RejectUnsupported*
// (IP ancillary, termios, recverr, remaining IPv4, listen-backlog). lockfile=
// / waitlock= run next. If the opener returns an error, OpenSpec releases
// that address lock only; it does not close sockets, files, or children the
// opener already acquired. The opener must clean those up before returning.
// The opener itself runs under WithNetNS. children-shutup is recorded on the
// Opened after success; a parse error there does Close the Opened. On success
// the address-lock release is attached as an Opened cleanup.
//
// What happens inside the opener is not one sequence.
//
// Stream listen (TCP, UNIX, TLS-LISTEN, WS-LISTEN, …) creates the socket with
// ListenControl: ApplyPastSocketPhase then ApplyListenOptions (reuse/v6only
// plus setsockopt-listen) before bind. OpenListenSession then compiles the peer
// filter, then either returns a fork parent or accepts one connection. Accept
// wait honors context and accept-timeout by aborting the listener. TCP accept
// applies connected options then SetupConnectedStream.
// UNIX listen applies remaining descriptor options on the accepted socket
// (owner options already ran on the name or listen fd) then WrapAfterFD.
//
// Stream dial uses OpenDialed. DialControl applies ApplyPastSocketThenPrebind
// after socket() and before connect. A successful dial wraps through the
// opener's Wrap (default SetupStream). Fork CONNECT stores Dial/WrapDial and
// does not wrap until a child runs.
//
// DTLS and QUIC bind through ListenPacketWithOptions: ListenControl before
// bind, then late socket buffers, FD lifecycle, and connected generic
// setsockopt on the PacketConn. That helper does not wrap. QUIC then uses
// WrapOpened around the stream; the packet socket is not the transfer
// descriptor. DTLS wraps with WrapStream after handshake.
//
// UDP binds through listenPacketForSpec → udpListenConfig (ListenControl
// plus optional fork port reuse before bind). After bind it applies UDP
// conn options and WrapOpened.
//
// Files (OPEN/CREATE/FILE/…) open a path, apply named unlink/owner/locks,
// ApplyFDOptionsSkip on that *os.File, then WrapAfterFD. There is no bind
// phase.
//
// EXEC/SYSTEM/SHELL build a child, then either return a nofork placeholder
// (Run later calls runExecNoFork with the peer) or start pipes/socketpair/PTY
// and wrap the parent stream. Pipes and socketpair still run SetupStream on the
// parent stream; PTY applies master lifecycle then WrapAfterFD. Past-socket
// options are rejected on pipes/pty/nofork; socketpair can apply them on the
// child endpoint.
//
// SetupStream applies descriptor lifecycle and connected sockopts, then
// WrapOpened. SetupConnectedStream skips connected sockopts because the
// opener already applied or rejected them. WrapAfterFD is connected sockopts
// plus WrapOpened after the opener applied descriptor lifecycle. WrapOpened
// applies late socket buffers then WrapStream with StreamSocketTimeouts.
// WrapStream itself is descriptor-mode → (optional) stream-layer timeouts →
// ignoreeof → readbytes → crnl → escape → null-eof → shutdown policy →
// end-close.
//
// Timeouts are not always in WrapStream. TLS wraps the TCP conn with
// NewSocketTimeoutConn / EnableSocketTimeouts under the record layer, then
// WrapStream(..., TransportSocketTimeouts) so read/write deadlines are not
// applied again above TLS. WS/WSS handshake on the TCP conn, then
// SetupConnectedStream (StreamSocketTimeouts). DTLS uses StreamSocketTimeouts
// on the datagram stream.
package xio
