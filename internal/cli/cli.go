// Package cli implements the socat command-line interface.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat"
	"github.com/oittaa/socat/internal/addr"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

// Config holds parsed global options.
type Config struct {
	Help       int // 0 none, 1 -h, 2 -hh, 3 -hhh
	Version    bool
	LogLevel   logx.Level
	LogFile    string
	Progname   string
	Micros     bool
	Hostname   bool
	Verbose    bool
	Hex        bool
	BlockSize  int
	Sloppy     bool
	Linger     time.Duration
	Idle       time.Duration // <0 infinite, 0 zero, >0 timeout
	IdleSet    bool
	LeftToRight bool // -u
	RightToLeft bool // -U
	IP4        bool
	IP6        bool
	IPAny      bool
	Statistics bool
	LockFile   string
	LockWait   string
	RawLeft    string // -r
	RawRight   string // -R
	Addresses  []string
}

// ParseArgs parses os.Args-style arguments (without program name).
func ParseArgs(args []string) (*Config, error) {
	cfg := &Config{
		LogLevel:  logx.Warning,
		BlockSize: 8192,
		Linger:    500 * time.Millisecond,
		Idle:      -1, // infinite
		Progname:  "socat",
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			cfg.Addresses = append(cfg.Addresses, args[i+1:]...)
			break
		}
		// Addresses may start with '-' (STDIO synonym), '-,opts', or dual forms like '-!!-'.
		// Classic: "-,escape=27" is STDIO with options, not a CLI flag.
		if !strings.HasPrefix(a, "-") || a == "-" || strings.HasPrefix(a, "-,") ||
			strings.HasPrefix(a, "-!!") || strings.Contains(a, "!!") {
			cfg.Addresses = append(cfg.Addresses, a)
			continue
		}

		// Long options
		if a == "--statistics" {
			cfg.Statistics = true
			continue
		}
		if a == "--experimental" {
			continue
		}

		// Cluster short options carefully
		if err := parseOption(a, args, &i, cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func parseOption(a string, args []string, i *int, cfg *Config) error {
	// -d / -dd / -ddd / -dddd / -d0 / -d2 …
	if strings.HasPrefix(a, "-d") {
		rest := a[2:]
		if rest == "" {
			// each bare -d increases one level from current (min Notice)
			if cfg.LogLevel < logx.Notice {
				cfg.LogLevel = logx.Notice
			} else if cfg.LogLevel < logx.Debug {
				cfg.LogLevel++
			}
			return nil
		}
		if n, err := strconv.Atoi(rest); err == nil {
			cfg.LogLevel = levelFromN(n)
			return nil
		}
		// -dd, -ddd, -dddd
		if strings.Trim(rest, "d") == "" {
			cfg.LogLevel = levelFromN(len(rest) + 1) // -dd => 2 d's total with first d
			// a is -dd: rest="d" len 1 → levelFromN(2); better count all d's
			cfg.LogLevel = levelFromN(len(a) - 1)
			return nil
		}
	}

	switch {
	case a == "-h" || a == "-?" || a == "--help":
		cfg.Help = 1
	case a == "-hh" || a == "-??":
		cfg.Help = 2
	case a == "-hhh" || a == "-???":
		cfg.Help = 3
	case a == "-V":
		cfg.Version = true
	case a == "-v":
		cfg.Verbose = true
	case a == "-x":
		cfg.Hex = true
	case a == "-s":
		cfg.Sloppy = true
	case a == "-u":
		cfg.LeftToRight = true
	case a == "-U":
		cfg.RightToLeft = true
	case a == "-4":
		cfg.IP4 = true
	case a == "-6":
		cfg.IP6 = true
	case a == "-0":
		cfg.IPAny = true
	case a == "-S" || a == "--statistics":
		cfg.Statistics = true
	case a == "-lu":
		cfg.Micros = true
	case a == "-lh":
		cfg.Hostname = true
	case a == "-g":
		// ignore option group check
	case strings.HasPrefix(a, "-b"):
		v, err := optArg(a, "b", args, i)
		if err != nil {
			// Classic: bare/missing -b → "missing numerical value of option "-b""
			return fmt.Errorf("parseopts(): missing numerical value of option \"-b\"")
		}
		// Reject empty or non-numeric (classic overflow / missing value messages).
		if v == "" {
			return fmt.Errorf("parseopts(): missing numerical value of option \"-b\"")
		}
		// Parse as unsigned; overflow → "to big" (classic).
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			// value larger than uint64 or non-numeric
			if _, e2 := strconv.ParseFloat(v, 64); e2 == nil {
				return fmt.Errorf("buffer size option (-b) to big")
			}
			return fmt.Errorf("parseopts(): missing numerical value of option \"-b\"")
		}
		// max is math.MaxInt64 for signed size math in classic (SIZE_T related)
		const maxBuf = uint64(1<<63 - 1)
		if n == 0 || n > maxBuf {
			return fmt.Errorf("buffer size option (-b) to big")
		}
		// Also cap at a practical size to avoid OOM
		const practical = 256 * 1024 * 1024
		if n > practical {
			return fmt.Errorf("buffer size option (-b) to big")
		}
		cfg.BlockSize = int(n)
	case strings.HasPrefix(a, "-t"):
		v, err := optArg(a, "t", args, i)
		if err != nil {
			return err
		}
		cfg.Linger = parseDuration(v)
	case strings.HasPrefix(a, "-T"):
		v, err := optArg(a, "T", args, i)
		if err != nil {
			return err
		}
		cfg.IdleSet = true
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			cfg.Idle = parseDuration(v)
		} else if f < 0 {
			cfg.Idle = -1
		} else {
			cfg.Idle = time.Duration(f * float64(time.Second))
		}
	case strings.HasPrefix(a, "-lp"):
		v, err := optArg(a, "lp", args, i)
		if err != nil {
			return err
		}
		cfg.Progname = v
	case strings.HasPrefix(a, "-lf"):
		v, err := optArg(a, "lf", args, i)
		if err != nil {
			return err
		}
		cfg.LogFile = v
	case strings.HasPrefix(a, "-L"):
		v, err := optArg(a, "L", args, i)
		if err != nil {
			return err
		}
		cfg.LockFile = v
	case strings.HasPrefix(a, "-W"):
		v, err := optArg(a, "W", args, i)
		if err != nil {
			return err
		}
		cfg.LockWait = v
	case strings.HasPrefix(a, "-r") && !strings.HasPrefix(a, "-reuse"):
		v, err := optArg(a, "r", args, i)
		if err != nil {
			return err
		}
		cfg.RawLeft = v
	case strings.HasPrefix(a, "-R"):
		v, err := optArg(a, "R", args, i)
		if err != nil {
			return err
		}
		cfg.RawRight = v
	case a == "-D":
		// log FDs before transfer — future
	case a == "-ls":
		// log to stderr (default)
	default:
		// try multi -d as separate already handled
		if strings.HasPrefix(a, "-d") {
			cfg.LogLevel = logx.Notice
			return nil
		}
		return fmt.Errorf("unknown option %q", a)
	}
	return nil
}

func levelFromN(n int) logx.Level {
	// n = number of -d or -dn value
	// 0: error only (no warning)? classic -d0 fatal+error
	// 1: +notice
	// 2: +info  
	// 3: +debug? man: -ddd is info, -dddd debug
	switch {
	case n <= 0:
		return logx.Error
	case n == 1:
		return logx.Notice
	case n == 2:
		return logx.Info
	default:
		return logx.Debug
	}
}

func optArg(a, key string, args []string, i *int) (string, error) {
	// -b8192 or -b 8192 or -lpname or -lp name
	prefix := "-" + key
	if a == prefix {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("option %s requires an argument", prefix)
		}
		*i++
		return args[*i], nil
	}
	if strings.HasPrefix(a, prefix) {
		return a[len(prefix):], nil
	}
	return "", fmt.Errorf("option parse error for %s", a)
}

func parseDuration(v string) time.Duration {
	f, err := strconv.ParseFloat(v, 64)
	if err == nil {
		return time.Duration(f * float64(time.Second))
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0
	}
	return d
}

// Main runs socat with the given args (excluding program name).
func Main(args []string) int {
	cfg, err := ParseArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socat: %v\n", err)
		return 1
	}

	if cfg.Version {
		printVersion(os.Stdout)
		return 0
	}
	if cfg.Help > 0 {
		printHelp(os.Stdout, cfg.Help)
		return 0
	}

	if len(cfg.Addresses) != 2 {
		fmt.Fprintf(os.Stderr, "socat: exactly two addresses required (got %d)\n", len(cfg.Addresses))
		printHelp(os.Stderr, 1)
		return 1
	}

	log := logx.New()
	log.SetLevel(cfg.LogLevel)
	log.SetProgname(cfg.Progname)
	log.SetMicros(cfg.Micros)
	if cfg.Hostname {
		h, _ := os.Hostname()
		log.SetHostname(h)
	}
	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "socat: %v\n", err)
			return 1
		}
		defer f.Close()
		log.SetOutput(f)
	}

	// Lock files
	if cfg.LockFile != "" {
		if _, err := os.Stat(cfg.LockFile); err == nil {
			fmt.Fprintf(os.Stderr, "socat: lockfile %s exists\n", cfg.LockFile)
			return 1
		}
		if err := os.WriteFile(cfg.LockFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "socat: %v\n", err)
			return 1
		}
		defer os.Remove(cfg.LockFile)
	}
	if cfg.LockWait != "" {
		for {
			if _, err := os.Stat(cfg.LockWait); os.IsNotExist(err) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err := os.WriteFile(cfg.LockWait, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "socat: %v\n", err)
			return 1
		}
		defer os.Remove(cfg.LockWait)
	}

	left, err := parse.ParseChannel(cfg.Addresses[0])
	if err != nil {
		log.Errorf("parse left address: %s", err)
		return 1
	}
	right, err := parse.ParseChannel(cfg.Addresses[1])
	if err != nil {
		log.Errorf("parse right address: %s", err)
		return 1
	}

	g := &addr.Global{
		Log:         log,
		BlockSize:   cfg.BlockSize,
		Linger:      cfg.Linger,
		Verbose:     cfg.Verbose,
		Hex:         cfg.Hex,
		Dump:        os.Stderr,
		Statistics:  cfg.Statistics,
		Sloppy:      cfg.Sloppy,
		LeftToRight: cfg.LeftToRight,
		RightToLeft: cfg.RightToLeft,
	}
	// Classic -r / -R: path templates; opened at transfer start with expandenv
	// ($PROGNAME, $TIMESTAMP, $MICROS, $$, $PEER env after accept).
	g.RawLeftPath = cfg.RawLeft
	g.RawRightPath = cfg.RawRight
	if cfg.Progname != "" {
		g.Progname = cfg.Progname
	} else {
		g.Progname = "socat"
	}
	if cfg.IdleSet {
		if cfg.Idle < 0 {
			g.Idle = 0 // disabled in relay when 0
		} else {
			g.Idle = cfg.Idle
		}
	}
	// IP version: explicit -4/-6/-0 vs default (env SOCAT_DEFAULT_LISTEN_IP may apply to listen).
	switch {
	case cfg.IPAny:
		g.IPVersion = addr.IPvAny
	case cfg.IP6:
		g.IPVersion = addr.IPv6
	case cfg.IP4:
		g.IPVersion = addr.IPv4
	default:
		g.IPVersion = addr.IPvDefault
	}

	// Classic EXITCODESIG*: dying on SIGTERM/ILL/… exits with 128+signum.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGILL, syscall.SIGQUIT, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sig := <-sigCh
		cancel()
		if ss, ok := sig.(syscall.Signal); ok && ss > 0 {
			// Exit immediately so Wait()-blocked nofork paths still report classic status.
			os.Exit(128 + int(ss))
		}
	}()

	runErr := addr.Run(ctx, left, right, g)
	if runErr != nil {
		if ctx.Err() != nil {
			if g.ChildExitCode != 0 {
				return g.ChildExitCode
			}
			return 0
		}
		// Classic socat exits 0 when accept-timeout fires with no peer.
		if runErr == addr.ErrAcceptTimeout {
			return 0
		}
		log.Errorf("%s", runErr)
		return 1
	}
	// EXEC_RC / SYSTEM_RC: promote child non-zero exit.
	if g.ChildExitCode != 0 {
		return g.ChildExitCode
	}
	return 0
}

func printVersion(w io.Writer) {
	// Format compatible with classic test.sh testfeats() which greps:
	//   #define WITH_FOO 1
	fmt.Fprintf(w, "socat version %s on %s\n", socat.Version, time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "   running on Go reimplementation (github.com/oittaa/socat)\n")
	fmt.Fprintln(w, "features:")
	// Implemented = 1, not yet = 0. Keep names aligned with classic socat -V.
	feats := []struct {
		name string
		on   bool
	}{
		// Honesty: only set 1 for features that actually work end-to-end.
		{"HELP", true},
		{"STATS", false}, // --statistics partial; SIGUSR1 not implemented
		{"STDIO", true},
		{"FDNUM", true},
		{"FILE", true},
		{"CREAT", true},
		{"GOPEN", true},
		{"TERMIOS", false},
		{"PIPE", true},
		{"STALL", true},
		{"TEXT", true},
		{"SOCKETPAIR", true},
		{"UNIX", true},
		{"ABSTRACT_UNIXSOCKET", true},
		{"IP4", true},
		{"IP6", true},
		{"RAWIP", true},
		{"GENERICSOCKET", false},
		{"INTERFACE", false},
		{"TCP", true},
		{"UDP", true},
		{"SCTP", false},
		{"DCCP", false},
		{"UDPLITE", false},
		{"LISTEN", true},
		{"POSIXMQ", false},
		{"SOCKS4", true},
		{"SOCKS4A", true},
		{"SOCKS5", true},
		{"VSOCK", false},
		{"NAMESPACES", false},
		{"PROXY", true},
		{"SYSTEM", true},
		{"SHELL", true},
		{"EXEC", true},
		{"READLINE", false},
		{"TUN", false},
		{"PTY", true},
		{"OPENSSL", true}, // stream TLS via crypto/tls (not DTLS)
		{"FIPS", false},
		{"LIBWRAP", false},
	}
	for _, f := range feats {
		if f.on {
			fmt.Fprintf(w, "  #define WITH_%s 1\n", f.name)
		} else {
			fmt.Fprintf(w, "  #undef WITH_%s\n", f.name)
		}
	}
}

func printHelp(w io.Writer, level int) {
	fmt.Fprintf(w, "socat %s by oittaa — multipurpose relay (Go)\n", socat.Version)
	fmt.Fprintf(w, "Usage: socat [options] <address> <address>\n")
	fmt.Fprintf(w, "       socat -V | -h[h[h]]\n\n")
	fmt.Fprintf(w, "Options:\n")
	fmt.Fprintf(w, "  -V              print version\n")
	fmt.Fprintf(w, "  -h|-?           print help\n")
	fmt.Fprintf(w, "  -d|-d0..-d4     increase verbosity\n")
	fmt.Fprintf(w, "  -v              verbose data dump (text)\n")
	fmt.Fprintf(w, "  -x              verbose data dump (hex)\n")
	fmt.Fprintf(w, "  -b<size>        transfer block size (default 8192)\n")
	fmt.Fprintf(w, "  -t<time>        linger after EOF (default 0.5s)\n")
	fmt.Fprintf(w, "  -T<time>        inactivity timeout\n")
	fmt.Fprintf(w, "  -u              unidirectional left→right\n")
	fmt.Fprintf(w, "  -U              unidirectional right→left\n")
	// Classic test.sh greps: [[:space:]]-4[[:space:]], -6, -0 on separate lines.
	fmt.Fprintf(w, "  -4     prefer IPv4 if version is not explicitly specified\n")
	fmt.Fprintf(w, "  -6     prefer IPv6 if version is not explicitly specified\n")
	fmt.Fprintf(w, "  -0     do not prefer an IP version\n")
	fmt.Fprintf(w, "  --statistics    print transfer statistics\n")
	// Address type names on -h (level>=1): classic test.sh runstcp4 greps
	// `$SOCAT -h | grep -i ' TCP4-'` etc.
	fmt.Fprintf(w, "\nAddress types:\n")
	fmt.Fprintf(w, "  STDIO STDIN STDOUT STDERR FD PIPE FIFO ECHO OPEN FILE CREATE CREAT GOPEN\n")
	fmt.Fprintf(w, "  TCP TCP4 TCP6 TCP-CONNECT TCP4-CONNECT TCP6-CONNECT\n")
	fmt.Fprintf(w, "  TCP-LISTEN TCP4-LISTEN TCP6-LISTEN TCP-L TCP4-L TCP6-L\n")
	fmt.Fprintf(w, "  UDP UDP4 UDP6 UDP-CONNECT UDP4-CONNECT UDP6-CONNECT\n")
	fmt.Fprintf(w, "  UDP-LISTEN UDP4-LISTEN UDP6-LISTEN UDP-L UDP4-L UDP6-L\n")
	fmt.Fprintf(w, "  UDP-SENDTO UDP4-SENDTO UDP6-SENDTO UDP-SEND UDP4-SEND UDP6-SEND\n")
	fmt.Fprintf(w, "  UDP-DATAGRAM UDP4-DATAGRAM UDP6-DATAGRAM\n")
	fmt.Fprintf(w, "  UDP-RECV UDP4-RECV UDP6-RECV UDP-RECVFROM UDP4-RECVFROM UDP6-RECVFROM\n")
	fmt.Fprintf(w, "  IP IP4 IP6 IP-SENDTO IP4-SENDTO IP6-SENDTO IP-DATAGRAM IP4-DATAGRAM IP6-DATAGRAM\n")
	fmt.Fprintf(w, "  IP-RECV IP4-RECV IP6-RECV IP-RECVFROM IP4-RECVFROM IP6-RECVFROM\n")
	fmt.Fprintf(w, "  UNIX UNIX-CONNECT UNIX-CLIENT UNIX-LISTEN UNIX-L\n")
	fmt.Fprintf(w, "  UNIX-SENDTO UNIX-RECVFROM UNIX-RECV UNIX-DATAGRAM SOCKETPAIR\n")
	fmt.Fprintf(w, "  SOCKET-CONNECT SOCKET-LISTEN SOCKET-SENDTO SOCKET-DATAGRAM SOCKET-RECV SOCKET-RECVFROM\n")
	fmt.Fprintf(w, "  ABSTRACT-LISTEN ABSTRACT-L ABSTRACT-CLIENT ABSTRACT-CONNECT\n")
	fmt.Fprintf(w, "  ABSTRACT-SENDTO ABSTRACT-RECVFROM ABSTRACT-RECV\n")
	fmt.Fprintf(w, "  EXEC SYSTEM SHELL TEXT STALL PTY\n")
	fmt.Fprintf(w, "  OPENSSL OPENSSL-CONNECT OPENSSL-LISTEN OPENSSL-L SSL SSL-CONNECT SSL-LISTEN SSL-L\n")
	fmt.Fprintf(w, "  PROXY PROXY-CONNECT SOCKS4 SOCKS4A SOCKS5 SOCKS5-CONNECT\n")
	if level >= 2 {
		// Honesty: only list options we actually honor. test.sh greps
		//   [^a-z0-9-]<name>[^a-z0-9-]  — pad with spaces on both sides.
		// Security filters range/sourceport/lowport are enforced on accept.
		opts := []string{
			"reuseaddr", "so-reuseaddr",
			"fork", "bind", "connect-timeout", "accept-timeout",
			"unlink-early", "unlink-close", "unlink-late", "mode", "nonblock", "o-nonblock",
			"rdonly", "wronly", "creat", "create", "excl", "append", "trunc", "o-append",
			"umask", "perm", "mode", "user", "group",
			"nodelay", "tcp-nodelay", "keepalive", "so-keepalive",
			"pipes", "setsid", "stderr", "pty",
			"pf", "sourceport", "sp",
			"range", "lowport", "setsockopt",
			"cert", "key", "cafile", "ca", "verify", "commonname", "openssl-commonname",
			// SNI: OPENSSL_SNI / OPENSSL_NO_SNI greps; snihost is classic alias.
			"openssl-snihost", "snihost", "openssl-no-sni", "nosni",
			// Multi-address resolve (TRY_ADDRS_4_6); filter when true.
			"ai-addrconfig", "addrconfig",
			// PROXY / SOCKS
			"proxyport", "http-version", "crlf", "socksport", "socksuser", "sockspass", "sockspassword",
			"crnl", "ignoreeof", "readbytes",
			"retry", "forever", "interval",
			"backlog", "fdin", "fdout", "max-children",
			"ipv6-v6only", "broadcast", "ip-add-membership",
			"link", "symbolic-link", "cfmakeraw", "raw", "rawer",
			"echo", "opost", "perm", "ispeed", "ospeed",
			"escape",
			// shut-none: do not SIGKILL EXEC/SYSTEM children (EXEC_RC / SYSTEM_RC).
			// shut-null / null-eof: 0-byte datagram as half-close (UDP etc.).
			"shut-none", "shut-null", "null-eof", "shut", "end-close", "nofork",
			// UDP/IP ancillary (SCM/ENV classic tests): recv enable + send values.
			"so-timestamp", "timestamp",
			"ip-pktinfo", "pktinfo",
			"ip-recvttl", "recvttl",
			"ip-recvtos", "recvtos",
			"ip-recvopts", "recvopts",
			"ip-ttl", "ttl", "ip-tos", "tos", "ip-options",
			"ipv6-recvpktinfo", "recvpktinfo",
			"ipv6-recvhoplimit", "recvhoplimit",
			"ipv6-recvtclass", "recvtclass",
			"ipv6-unicast-hops", "unicast-hops",
			"ipv6-tclass", "tclass",
		}
		fmt.Fprintln(w)
		fmt.Fprint(w, "b:")
		for _, o := range opts {
			fmt.Fprintf(w, " %s ", o)
		}
		fmt.Fprintln(w)
	}
	if level >= 3 {
		fmt.Fprintf(w, "\nCommon options: reuseaddr,fork,bind,connect-timeout,unlink-early,mode,pipes,setsid\n")
	}
}
