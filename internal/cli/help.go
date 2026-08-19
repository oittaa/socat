package cli

import (
	"io"

	"github.com/oittaa/socat"
	"github.com/oittaa/socat/internal/xio"
)

type helpAddr struct {
	syntax string
	desc   string
}

type helpAddrGroup struct {
	title string
	addrs []helpAddr
}

type helpOpt struct {
	name    string
	desc    string
	aliases []string
}

type helpOptGroup struct {
	title string
	opts  []helpOpt
}

func hideAddr(syntax string) bool {
	switch {
	case syntax == "SOCKETPAIR":
		return !xio.FeatureSOCKETPAIR
	case syntax == "STALL":
		return !xio.FeatureSTALL
	case syntax == "PTY":
		return !xio.FeaturePTY
	case syntax == "UNIX-SENDTO:<filename>" ||
		syntax == "UNIX-RECVFROM:<filename>" ||
		syntax == "UNIX-RECV:<filename>" ||
		syntax == "UNIX-DATAGRAM:<filename>":
		return !xio.FeatureUNIXDatagram
	case len(syntax) >= 9 && syntax[:9] == "ABSTRACT-":
		return !xio.FeatureABSTRACT
	case len(syntax) >= 3 && (syntax[:3] == "IP:" || syntax[:3] == "IP4" || syntax[:3] == "IP6" || syntax[:3] == "IP-"):
		return !xio.FeatureRAWIP
	case len(syntax) >= 7 && syntax[:7] == "SOCKET-":
		return !xio.FeatureGENERICSOCKET
	case syntax == "EXEC:<command-line>" || syntax == "SYSTEM:<shell-command>" || len(syntax) >= 5 && syntax[:5] == "SHELL":
		return !xio.FeatureEXEC
	case syntax == "TUN[:<ip>/<bits>]" || len(syntax) >= 10 && syntax[:10] == "INTERFACE:":
		return !xio.FeatureTUN && !xio.FeatureINTERFACE
	case len(syntax) >= 4 && syntax[:4] == "SCTP":
		return !xio.FeatureSCTP
	case len(syntax) >= 7 && syntax[:7] == "POSIXMQ":
		return !xio.FeaturePOSIXMQ
	default:
		return false
	}
}

func unixGenericHelp() string {
	switch {
	case xio.FeatureUNIXSeqpacket:
		return "generic UNIX client; auto-detects stream, seqpacket, or datagram"
	case xio.FeatureUNIXDatagram:
		return "generic UNIX client; auto-detects stream or datagram"
	default:
		return "UNIX stream client"
	}
}

func unixConnectHelp() string {
	switch {
	case xio.FeatureUNIXSeqpacket:
		return "UNIX stream client; socktype=2/5 selects datagram/seqpacket"
	case xio.FeatureUNIXDatagram:
		return "UNIX stream client; socktype=2 selects datagram"
	default:
		return "UNIX stream client"
	}
}

func unixListenHelp() string {
	if xio.FeatureUNIXSeqpacket {
		return "UNIX stream listener; socktype=5 selects seqpacket"
	}
	return "UNIX stream listener"
}

func unixSocktypeHelp() string {
	switch {
	case xio.FeatureUNIXSeqpacket:
		return "UNIX type: 1=stream, 2=datagram, 5=seqpacket"
	case xio.FeatureUNIXDatagram:
		return "UNIX type: 1=stream, 2=datagram"
	default:
		return "UNIX type: 1=stream"
	}
}

func hideOptGroup(title string) bool {
	switch title {
	case "PTY and TERMIOS":
		return !xio.FeaturePTY && !xio.FeatureTERMIOS
	case "POSIX message queues":
		return !xio.FeaturePOSIXMQ
	case "TUN and INTERFACE":
		return !xio.FeatureTUN && !xio.FeatureINTERFACE
	case "Namespaces":
		return !xio.FeatureNAMESPACES
	default:
		return false
	}
}

func printHelp(w io.Writer, level int) {
	fprintf(w, "socat %s by oittaa — multipurpose relay (Go)\n\n", socat.Version)
	fprintf(w, "Usage:\n")
	fprintf(w, "  socat [options] <address> <address>\n")
	fprintf(w, "  socat -V | -h | -hh | -hhh\n\n")
	fprintf(w, "  <address> is TYPE:params,option=value,...\n")
	fprintf(w, "  Use - for STDIO.  -h lists types; -hh lists options; -hhh adds aliases.\n\n")
	fprintf(w, "Example (TLS tunnel in front of a plain TCP service):\n")
	fprintf(w, "  socat TLS-LISTEN:8443,reuseaddr,fork,cert=s.crt,key=s.key,verify=0 TCP:127.0.0.1:8080\n\n")

	printHelpFlags(w)
	printHelpAddresses(w)
	if level >= 2 {
		printHelpOptions(w, level >= 3)
	}
}

func printHelpFlags(w io.Writer) {
	fprintf(w, "Options:\n")
	fprintf(w, "  -V              print version and features\n")
	fprintf(w, "  -h|-?           print help\n")
	fprintf(w, "  -hh             help plus honored address options\n")
	fprintf(w, "  -hhh            help plus options, aliases, and termios names\n")
	fprintf(w, "  -d|-d0..-d4     increase verbosity\n")
	fprintf(w, "  -v              verbose data dump (text)\n")
	fprintf(w, "  -x              verbose data dump (hex)\n")
	fprintf(w, "  -b<size>        transfer block size (default 8192)\n")
	fprintf(w, "  -t<time>        linger after EOF (default 0.5s)\n")
	fprintf(w, "  -T<time>        inactivity timeout\n")
	fprintf(w, "  -u              unidirectional left→right\n")
	fprintf(w, "  -U              unidirectional right→left\n")
	// Classic test.sh OPTION_RAW_DUMP greps: [[:space:]]-[rR][[:space:]]
	fprintf(w, "  -r <file>       dump left-to-right raw data\n")
	fprintf(w, "  -R <file>       dump right-to-left raw data\n")
	// Classic test.sh greps: [[:space:]]-4[[:space:]], -6, -0 on separate lines.
	fprintf(w, "  -4     prefer IPv4 if version is not explicitly specified\n")
	fprintf(w, "  -6     prefer IPv6 if version is not explicitly specified\n")
	fprintf(w, "  -0     do not prefer an IP version\n")
	fprintf(w, "  --statistics   output transfer statistics on exit\n")
	fprintf(w, "  --experimental allow experimental options (netns)\n")
}

func printHelpAddresses(w io.Writer) {
	fprintf(w, "\nAddress types:\n")
	for _, g := range helpAddressGroups() {
		var addrs []helpAddr
		width := 0
		for _, a := range g.addrs {
			if hideAddr(a.syntax) {
				continue
			}
			addrs = append(addrs, a)
			if n := len(a.syntax); n > width {
				width = n
			}
		}
		if len(addrs) == 0 {
			continue
		}
		fprintf(w, "\n  %s\n", g.title)
		for _, a := range addrs {
			fprintf(w, "    %-*s  %s\n", width, a.syntax, a.desc)
		}
	}
}

func printHelpOptions(w io.Writer, all bool) {
	fprintf(w, "\nAddress options:\n")
	fprintf(w, "  Form: option or option=value. Only honored names are listed.\n")
	groups := helpOptionGroups()
	width := 0
	for _, g := range groups {
		if hideOptGroup(g.title) {
			continue
		}
		for _, o := range g.opts {
			if hideOpt(o.name) {
				continue
			}
			if n := len(o.name); n > width {
				width = n
			}
			if all {
				for _, al := range o.aliases {
					if n := len(al); n > width {
						width = n
					}
				}
			}
		}
	}
	extra := extraHelpNames(all)
	for _, name := range extra {
		if n := len(name); n > width {
			width = n
		}
	}
	for _, g := range groups {
		if hideOptGroup(g.title) {
			continue
		}
		printedTitle := false
		for _, o := range g.opts {
			if hideOpt(o.name) {
				continue
			}
			if !printedTitle {
				fprintf(w, "\n  %s\n", g.title)
				printedTitle = true
			}
			printOptLine(w, o.name, o.desc, width)
			if all {
				for _, al := range o.aliases {
					printOptLine(w, al, "alias of "+o.name, width)
				}
			}
		}
	}
	if len(extra) == 0 {
		return
	}
	fprintf(w, "\n  Termios and baud (PTY / TTY)\n")
	for _, name := range extra {
		printOptLine(w, name, "termios flag or baud name", width)
	}
}

func printOptLine(w io.Writer, name, desc string, width int) {
	// Space on both sides of the name: test.sh testoptions and e2e use
	// [^a-z0-9-]<name>[^a-z0-9-] / " "+name+" ".
	fprintf(w, "    %-*s  %s\n", width, name, desc)
}

func extraHelpNames(all bool) []string {
	if !all {
		return nil
	}
	skip := map[string]struct{}{}
	for _, g := range helpOptionGroups() {
		for _, o := range g.opts {
			skip[o.name] = struct{}{}
			for _, al := range o.aliases {
				skip[al] = struct{}{}
			}
		}
	}
	var out []string
	for _, name := range xio.TermiosHelpNames() {
		if _, dup := skip[name]; dup {
			continue
		}
		skip[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func helpAddressGroups() []helpAddrGroup {
	return []helpAddrGroup{
		{"Files and stdio", []helpAddr{
			{"STDIO", "standard input and output (also -)"},
			{"STDIN", "standard input"},
			{"STDOUT", "standard output"},
			{"STDERR", "standard error"},
			{"FD:<fdnum>", "existing file descriptor"},
			{"PIPE[:<filename>]", "anonymous pipe or named FIFO"},
			{"FIFO[:<filename>]", "same as PIPE"},
			{"ECHO", "same as PIPE"},
			{"OPEN:<filename>", "open a file"},
			{"FILE:<filename>", "same as OPEN"},
			{"CREATE:<filename>", "create or truncate a file"},
			{"CREAT:<filename>", "same as CREATE"},
			{"GOPEN:<filename>", "open or create a file (or socket)"},
			{"SOCKETPAIR", "unnamed UNIX socket pair"},
			{"TEXT:<string>", "write a fixed string, then EOF"},
			{"STALL", "block writes (full-pipe backpressure)"},
			{"PTY", "allocate a pseudo-terminal"},
		}},
		{"TCP", []helpAddr{
			{"TCP:<host>:<port>", "TCP client"},
			{"TCP-CONNECT:<host>:<port>", "same as TCP"},
			{"TCP4:<host>:<port>", "IPv4 TCP client"},
			{"TCP4-CONNECT:<host>:<port>", "same as TCP4"},
			{"TCP6:<host>:<port>", "IPv6 TCP client"},
			{"TCP6-CONNECT:<host>:<port>", "same as TCP6"},
			{"TCP-LISTEN:<port>", "TCP server"},
			{"TCP-L:<port>", "same as TCP-LISTEN"},
			{"TCP4-LISTEN:<port>", "IPv4 TCP server"},
			{"TCP4-L:<port>", "same as TCP4-LISTEN"},
			{"TCP6-LISTEN:<port>", "IPv6 TCP server"},
			{"TCP6-L:<port>", "same as TCP6-LISTEN"},
		}},
		{"UDP", []helpAddr{
			{"UDP:<host>:<port>", "UDP client"},
			{"UDP-CONNECT:<host>:<port>", "same as UDP"},
			{"UDP4:<host>:<port>", "IPv4 UDP client"},
			{"UDP4-CONNECT:<host>:<port>", "same as UDP4"},
			{"UDP6:<host>:<port>", "IPv6 UDP client"},
			{"UDP6-CONNECT:<host>:<port>", "same as UDP6"},
			{"UDP-LISTEN:<port>", "UDP server"},
			{"UDP-L:<port>", "same as UDP-LISTEN"},
			{"UDP4-LISTEN:<port>", "IPv4 UDP server"},
			{"UDP4-L:<port>", "same as UDP4-LISTEN"},
			{"UDP6-LISTEN:<port>", "IPv6 UDP server"},
			{"UDP6-L:<port>", "same as UDP6-LISTEN"},
			{"UDP-SENDTO:<host>:<port>", "UDP send to one peer"},
			{"UDP-SEND:<host>:<port>", "same as UDP-SENDTO"},
			{"UDP4-SENDTO:<host>:<port>", "IPv4 UDP send to one peer"},
			{"UDP4-SEND:<host>:<port>", "same as UDP4-SENDTO"},
			{"UDP6-SENDTO:<host>:<port>", "IPv6 UDP send to one peer"},
			{"UDP6-SEND:<host>:<port>", "same as UDP6-SENDTO"},
			{"UDP-DATAGRAM:<host>:<port>", "connected UDP datagram"},
			{"UDP4-DATAGRAM:<host>:<port>", "IPv4 UDP datagram"},
			{"UDP6-DATAGRAM:<host>:<port>", "IPv6 UDP datagram"},
			{"UDP-RECV:<port>", "receive UDP; ignore source"},
			{"UDP4-RECV:<port>", "IPv4 UDP receive"},
			{"UDP6-RECV:<port>", "IPv6 UDP receive"},
			{"UDP-RECVFROM:<port>", "receive one UDP datagram, reply to sender"},
			{"UDP4-RECVFROM:<port>", "IPv4 UDP recvfrom"},
			{"UDP6-RECVFROM:<port>", "IPv6 UDP recvfrom"},
		}},
		{"Raw IP", []helpAddr{
			{"IP:<host>:<protocol>", "raw IP send/receive"},
			{"IP4:<host>:<protocol>", "IPv4 raw IP"},
			{"IP6:<host>:<protocol>", "IPv6 raw IP"},
			{"IP-SENDTO:<host>:<protocol>", "raw IP send to one peer"},
			{"IP4-SENDTO:<host>:<protocol>", "IPv4 raw IP sendto"},
			{"IP6-SENDTO:<host>:<protocol>", "IPv6 raw IP sendto"},
			{"IP-DATAGRAM:<host>:<protocol>", "raw IP datagram"},
			{"IP4-DATAGRAM:<host>:<protocol>", "IPv4 raw IP datagram"},
			{"IP6-DATAGRAM:<host>:<protocol>", "IPv6 raw IP datagram"},
			{"IP-RECV:<protocol>", "raw IP receive"},
			{"IP4-RECV:<protocol>", "IPv4 raw IP receive"},
			{"IP6-RECV:<protocol>", "IPv6 raw IP receive"},
			{"IP-RECVFROM:<protocol>", "raw IP recvfrom"},
			{"IP4-RECVFROM:<protocol>", "IPv4 raw IP recvfrom"},
			{"IP6-RECVFROM:<protocol>", "IPv6 raw IP recvfrom"},
		}},
		{"UNIX and abstract", []helpAddr{
			{"UNIX:<filename>", unixGenericHelp()},
			{"UNIX-CONNECT:<filename>", unixConnectHelp()},
			{"UNIX-CLIENT:<filename>", unixGenericHelp()},
			{"UNIX-LISTEN:<filename>", unixListenHelp()},
			{"UNIX-L:<filename>", "same as UNIX-LISTEN"},
			{"UNIX-SENDTO:<filename>", "UNIX datagram sendto"},
			{"UNIX-RECVFROM:<filename>", "UNIX datagram recvfrom"},
			{"UNIX-RECV:<filename>", "UNIX datagram receive"},
			{"UNIX-DATAGRAM:<filename>", "UNIX datagram"},
			{"ABSTRACT-CONNECT:<name>", "Linux abstract UNIX client"},
			{"ABSTRACT-CLIENT:<name>", "same as ABSTRACT-CONNECT"},
			{"ABSTRACT-LISTEN:<name>", "Linux abstract UNIX server"},
			{"ABSTRACT-L:<name>", "same as ABSTRACT-LISTEN"},
			{"ABSTRACT-SENDTO:<name>", "Linux abstract UNIX sendto"},
			{"ABSTRACT-RECVFROM:<name>", "Linux abstract UNIX recvfrom"},
			{"ABSTRACT-RECV:<name>", "Linux abstract UNIX receive"},
		}},
		{"Generic socket", []helpAddr{
			{"SOCKET-CONNECT:<dom>:<proto>:<addr>", "generic socket connect"},
			{"SOCKET-LISTEN:<dom>:<proto>:<addr>", "generic socket listen"},
			{"SOCKET-SENDTO:<dom>:<type>:<proto>:<addr>", "generic sendto"},
			{"SOCKET-DATAGRAM:<dom>:<type>:<proto>:<addr>", "generic datagram"},
			{"SOCKET-RECV:<dom>:<type>:<proto>:<addr>", "generic receive"},
			{"SOCKET-RECVFROM:<dom>:<type>:<proto>:<addr>", "generic recvfrom"},
		}},
		{"Process", []helpAddr{
			{"EXEC:<command-line>", "run a program (argv)"},
			{"SYSTEM:<shell-command>", "run a shell command"},
			{"SHELL[:<shell-command>]", "interactive shell or command"},
		}},
		{"TLS (OPENSSL/SSL aliases)", []helpAddr{
			{"TLS:<host>:<port>", "TLS client (stream TLS, not DTLS)"},
			{"TLS-CONNECT:<host>:<port>", "same as TLS"},
			{"TLS-LISTEN:<port>", "TLS server; requires cert="},
			{"TLS-L:<port>", "same as TLS-LISTEN"},
			{"OPENSSL:<host>:<port>", "alias of TLS"},
			{"OPENSSL-CONNECT:<host>:<port>", "alias of TLS-CONNECT"},
			{"OPENSSL-LISTEN:<port>", "alias of TLS-LISTEN"},
			{"OPENSSL-L:<port>", "alias of TLS-L"},
			{"SSL:<host>:<port>", "alias of TLS"},
			{"SSL-CONNECT:<host>:<port>", "alias of TLS-CONNECT"},
			{"SSL-LISTEN:<port>", "alias of TLS-LISTEN"},
			{"SSL-L:<port>", "alias of TLS-L"},
		}},
		{"PROXY and SOCKS", []helpAddr{
			{"PROXY:<proxy>:<host>:<port>", "HTTP CONNECT client"},
			{"PROXY-CONNECT:<proxy>:<host>:<port>", "same as PROXY"},
			{"SOCKS4:<socks>:<host>:<port>", "SOCKS4 client"},
			{"SOCKS4A:<socks>:<host>:<port>", "SOCKS4a client"},
			{"SOCKS5:<socks>:<host>:<port>", "SOCKS5 client"},
			{"SOCKS5-CONNECT:<socks>:<host>:<port>", "same as SOCKS5"},
			{"SOCKS5-LISTEN:<socks>:<host>:<port>", "SOCKS5 BIND (remote listen)"},
			{"SOCKS5-BIND:<socks>:<host>:<port>", "same as SOCKS5-LISTEN"},
		}},
		{"Linux TUN / INTERFACE", []helpAddr{
			{"TUN[:<ip>/<bits>]", "Linux TUN/TAP device"},
			{"INTERFACE:<ifname>", "Linux AF_PACKET interface"},
		}},
		{"WebSocket (Go extra)", []helpAddr{
			{"WS:<host>:<port>", "WebSocket client"},
			{"WS-CONNECT:<host>:<port>", "same as WS"},
			{"WSS:<host>:<port>", "WebSocket client over TLS"},
			{"WSS-CONNECT:<host>:<port>", "same as WSS"},
			{"WS-LISTEN:<port>", "WebSocket server"},
			{"WS-L:<port>", "same as WS-LISTEN"},
			{"WSS-LISTEN:<port>", "WebSocket server over TLS; requires cert="},
			{"WSS-L:<port>", "same as WSS-LISTEN"},
		}},
		{"QUIC (Go extra, not HTTP/3)", []helpAddr{
			{"QUIC:<host>:<port>", "QUIC byte pipe"},
			{"QUIC-CONNECT:<host>:<port>", "same as QUIC"},
			{"QUIC-LISTEN:<port>", "QUIC server; requires cert="},
			{"QUIC-L:<port>", "same as QUIC-LISTEN"},
		}},
		{"SCTP (Linux)", []helpAddr{
			{"SCTP:<host>:<port>", "SCTP client"},
			{"SCTP-CONNECT:<host>:<port>", "same as SCTP"},
			{"SCTP-LISTEN:<port>", "SCTP server"},
			{"SCTP-L:<port>", "same as SCTP-LISTEN"},
			{"SCTP4:<host>:<port>", "IPv4 SCTP client"},
			{"SCTP4-CONNECT:<host>:<port>", "same as SCTP4"},
			{"SCTP4-LISTEN:<port>", "IPv4 SCTP server"},
			{"SCTP4-L:<port>", "same as SCTP4-LISTEN"},
			{"SCTP6:<host>:<port>", "IPv6 SCTP client"},
			{"SCTP6-CONNECT:<host>:<port>", "same as SCTP6"},
			{"SCTP6-LISTEN:<port>", "IPv6 SCTP server"},
			{"SCTP6-L:<port>", "same as SCTP6-LISTEN"},
		}},
		{"POSIX message queues (Linux)", []helpAddr{
			{"POSIXMQ:<mqname>", "POSIX message queue (bidirectional)"},
			{"POSIXMQ-BIDIRECTIONAL:<mqname>", "same as POSIXMQ"},
			{"POSIXMQ-READ:<mqname>", "read a POSIX message queue"},
			{"POSIXMQ-RECEIVE:<mqname>", "same as POSIXMQ-RECV"},
			{"POSIXMQ-RECV:<mqname>", "receive from a POSIX message queue"},
			{"POSIXMQ-SEND:<mqname>", "send to a POSIX message queue"},
			{"POSIXMQ-WRITE:<mqname>", "same as POSIXMQ-SEND"},
		}},
	}
}

func helpOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"Listen and connect", []helpOpt{
			{"reuseaddr", "SO_REUSEADDR (default on for listen)", []string{"so-reuseaddr"}},
			{"reuseport", "SO_REUSEPORT", []string{"so-reuseport"}},
			{"fork", "new session per accept or client redial", nil},
			{"nofork", "do not fork (single session)", nil},
			{"max-children", "limit concurrent fork sessions (needs fork)", nil},
			{"bind", "local address or interface", nil},
			{"connect-timeout", "connect timeout", nil},
			{"handshake-timeout", "TLS, WebSocket, proxy, or SOCKS handshake timeout", nil},
			{"accept-timeout", "listen accept timeout (exit 0)", nil},
			{"backlog", "listen backlog", nil},
			{"pf", "address family (4, 6, IP4, IP6, …)", nil},
			{"ai-addrconfig", "getaddrinfo AI_ADDRCONFIG", []string{"addrconfig"}},
			{"ipv6-v6only", "IPV6_V6ONLY", nil},
			{"retry", "retry count on connect failure", nil},
			{"forever", "retry without limit", nil},
			{"interval", "retry or fork-redial interval", nil},
		}},
		{"Security filters", []helpOpt{
			{"range", "accept only peers in this network", nil},
			{"sourceport", "peer source port (listen) or bind port (connect)", []string{"sp"}},
			{"lowport", "require or bind a low source port", nil},
			{"tcpwrap", "apply hosts.allow / hosts.deny", []string{"tcpwrappers", "tcpwrapper", "libwrap", "wrap"}},
			{"tcpwrap-etc", "directory of hosts.allow / hosts.deny", []string{"tcpwrap-dir"}},
			{"hosts-allow", "allow table path", []string{"allow-table", "tcpwrap-hosts-allow-table"}},
			{"hosts-deny", "deny table path", []string{"deny-table", "tcpwrap-hosts-deny-table"}},
		}},
		{"Sockets", []helpOpt{
			{"nodelay", "TCP_NODELAY", []string{"tcp-nodelay"}},
			{"keepalive", "SO_KEEPALIVE", []string{"so-keepalive"}},
			{"broadcast", "SO_BROADCAST", nil},
			{"ip-add-membership", "IPv4 multicast join", nil},
			{"ipv6-join-group", "IPv6 multicast join", nil},
			{"setsockopt", "raw setsockopt (level, opt, value)", nil},
			{"so-timestamp", "SO_TIMESTAMP ancillary", []string{"timestamp"}},
			{"ip-pktinfo", "IP_PKTINFO", []string{"pktinfo"}},
			{"ip-recvttl", "IP_RECVTTL", []string{"recvttl"}},
			{"ip-recvtos", "IP_RECVTOS", []string{"recvtos"}},
			{"ip-recvopts", "IP_RECVOPTS", []string{"recvopts"}},
			{"ip-ttl", "IP_TTL", []string{"ttl"}},
			{"ip-tos", "IP_TOS", []string{"tos"}},
			{"ip-options", "IP_OPTIONS", nil},
			{"ipv6-recvpktinfo", "IPV6_RECVPKTINFO", []string{"recvpktinfo"}},
			{"ipv6-recvhoplimit", "IPV6_RECVHOPLIMIT", []string{"recvhoplimit"}},
			{"ipv6-recvtclass", "IPV6_RECVTCLASS", []string{"recvtclass"}},
			{"ipv6-unicast-hops", "IPV6_UNICAST_HOPS", []string{"unicast-hops"}},
			{"ipv6-tclass", "IPV6_TCLASS", []string{"tclass"}},
			{"rcvtimeo", "socket receive timeout", []string{"so-rcvtimeo"}},
		}},
		{"Files and UNIX", []helpOpt{
			{"rdonly", "open read-only", nil},
			{"wronly", "open write-only", nil},
			{"creat", "create the file", []string{"create"}},
			{"excl", "fail if the file exists", nil},
			{"append", "open append", []string{"o-append"}},
			{"trunc", "truncate on open", nil},
			{"nonblock", "O_NONBLOCK", []string{"o-nonblock"}},
			{"mode", "create mode bits", nil},
			{"perm", "chmod after open", nil},
			{"ftruncate", "truncate an opened file to this length", nil},
			{"umask", "umask during open or EXEC start", nil},
			{"user", "file owner", nil},
			{"group", "file group", nil},
			{"unlink-early", "unlink before bind/open", nil},
			{"unlink-close", "unlink on close", nil},
			{"unlink-late", "unlink after bind", nil},
			{"unix-bind-tempname", "bind a temporary UNIX name", []string{"bind-tempname"}},
			{"socktype", unixSocktypeHelp(), []string{"so-type"}},
		}},
		{"EXEC, SYSTEM, SHELL", []helpOpt{
			{"pipes", "connect with pipes", nil},
			{"pty", "run on a pseudo-terminal", nil},
			{"setsid", "new session", nil},
			{"stderr", "include child stderr", nil},
			{"fdin", "child stdin fd number", nil},
			{"fdout", "child stdout fd number", nil},
			{"shell", "use a shell", nil},
			{"chdir", "change directory before open or exec", nil},
			{"shut-none", "do not kill the child on close", nil},
			{"end-close", "close on EOF", nil},
			{"shut", "half-close mode", nil},
			{"shut-null", "0-byte datagram as half-close", []string{"null-eof"}},
		}},
		{"PTY and TERMIOS", []helpOpt{
			{"link", "symlink to the PTY slave", []string{"symbolic-link"}},
			{"cfmakeraw", "raw termios (cfmakeraw)", []string{"raw"}},
			{"rawer", "stricter raw termios", nil},
			{"echo", "terminal echo", nil},
			{"opost", "output post-processing", nil},
			{"ispeed", "input baud", nil},
			{"ospeed", "output baud", nil},
			{"tiocswinsz", "window size rows:cols", []string{"winsz"}},
			{"pty-wait-slave", "wait until the slave is open", []string{"wait-slave", "waitslave"}},
			{"pty-interval", "poll interval while waiting for slave", nil},
			{"ctty", "make the PTY the controlling tty", []string{"tiocsctty"}},
			{"ptmx", "open /dev/ptmx", nil},
			{"openpty", "use openpty(3)", nil},
			{"escape", "escape character", nil},
		}},
		{"Transfer", []helpOpt{
			{"crnl", "convert CR/NL", nil},
			{"crlf", "convert CR/LF", nil},
			{"crorlf", "convert CR or LF", nil},
			{"ignoreeof", "do not close on EOF", nil},
			{"readbytes", "read at most N bytes", nil},
		}},
		{"TLS, WSS, and QUIC", []helpOpt{
			{"cert", "certificate file (PEM); required on listen", nil},
			{"key", "private key file (PEM)", nil},
			{"cafile", "CA file (PEM or DER)", []string{"ca"}},
			{"capath", "directory of CA certificates", []string{"tls-capath", "openssl-capath"}},
			{"verify", "verify the peer (default on; 0 skips)", nil},
			{"commonname", "name to check (empty skips the name check)", []string{"tls-commonname", "openssl-commonname"}},
			{"snihost", "TLS SNI host name", []string{"tls-snihost", "openssl-snihost"}},
			{"nosni", "do not send SNI", []string{"tls-no-sni", "openssl-no-sni"}},
			{"alpn", "QUIC ALPN (default socat; not h3)", nil},
		}},
		{"WebSocket", []helpOpt{
			{"path", "WebSocket URL path", nil},
			{"origin", "WebSocket Origin header", nil},
			{"protocol", "WebSocket subprotocol", nil},
		}},
		{"PROXY and SOCKS", []helpOpt{
			{"proxyport", "HTTP proxy port", nil},
			{"http-version", "CONNECT HTTP version (1.0, 1.1, 2, 3)", nil},
			{"h2c", "cleartext HTTP/2 CONNECT", nil},
			{"proxy-resolve", "resolve CONNECT target locally", []string{"resolve"}},
			{"proxy-authorization", "proxy basic auth user:pass", []string{"proxyauth"}},
			{"proxy-authorization-file", "read proxy auth from a file", []string{"proxyauthfile"}},
			{"socksport", "SOCKS server port", nil},
			{"socksuser", "SOCKS user name", nil},
			{"sockspass", "SOCKS password", []string{"sockspassword"}},
		}},
		{"POSIX message queues", []helpOpt{
			{"mq-prio", "message priority", []string{"posixmq-priority"}},
			{"mq-flush", "drain the queue before use", []string{"posixmq-flush"}},
			{"mq-maxmsg", "mq_maxmsg", []string{"posixmq-maxmsg"}},
			{"mq-msgsize", "mq_msgsize", []string{"posixmq-msgsize"}},
		}},
		{"TUN and INTERFACE", []helpOpt{
			{"tun-device", "path to the TUN clone device", nil},
			{"tun-name", "TUN/TAP interface name", nil},
			{"tun-type", "tun or tap", nil},
			{"iff-no-pi", "no packet information header", []string{"no-pi"}},
			{"iff-up", "bring the interface up", []string{"up"}},
			{"iff-broadcast", "IFF_BROADCAST", nil},
			{"iff-debug", "IFF_DEBUG", nil},
			{"iff-loopback", "IFF_LOOPBACK", []string{"loopback"}},
			{"iff-pointopoint", "IFF_POINTOPOINT", []string{"pointopoint"}},
			{"iff-running", "IFF_RUNNING", []string{"running"}},
			{"iff-noarp", "IFF_NOARP", []string{"noarp"}},
			{"iff-promisc", "IFF_PROMISC", []string{"promisc"}},
			{"iff-allmulti", "IFF_ALLMULTI", []string{"allmulti"}},
			{"iff-multicast", "IFF_MULTICAST", nil},
			{"if-mtu", "interface MTU", []string{"interface-mtu"}},
		}},
		{"Namespaces", []helpOpt{
			{"netns", "open this address in a Linux network namespace", nil},
		}},
	}
}
