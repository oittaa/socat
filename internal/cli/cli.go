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
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

// Config holds parsed global options.
type Config struct {
	Help         int // 0 none, 1 -h, 2 -hh, 3 -hhh
	Version      bool
	LogLevel     logx.Level
	LogFile      string
	Progname     string
	Micros       bool
	Hostname     bool
	Verbose      bool
	Hex          bool
	BlockSize    int
	Sloppy       bool
	Linger       time.Duration
	Idle         time.Duration // <0 infinite, 0 zero, >0 timeout
	IdleSet      bool
	LeftToRight  bool // -u
	RightToLeft  bool // -U
	IP4          bool
	IP6          bool
	IPAny        bool
	Statistics   bool
	Experimental bool
	LockFile     string
	LockWait     string
	RawLeft      string // -r
	RawRight     string // -R
	Addresses    []string
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
			cfg.Experimental = true
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
	// Classic -S<sigmask> logs selected signals; not --statistics.
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
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) // #nosec G302 -- -lf log file is meant to be readable
		if err != nil {
			fmt.Fprintf(os.Stderr, "socat: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		log.SetOutput(f)
	}

	// Lock files: O_EXCL so two processes cannot both claim the same path.
	// Register for signal exit (os.Exit skips defers).
	if cfg.LockFile != "" {
		if err := createLockFile(cfg.LockFile); err != nil {
			fmt.Fprintf(os.Stderr, "socat: %v\n", err)
			return 1
		}
		xio.RegisterUnlinkPath(cfg.LockFile)
		defer func() { _ = os.Remove(cfg.LockFile) }()
	}
	if cfg.LockWait != "" {
		for {
			if _, err := os.Stat(cfg.LockWait); os.IsNotExist(err) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err := createLockFile(cfg.LockWait); err != nil {
			fmt.Fprintf(os.Stderr, "socat: %v\n", err)
			return 1
		}
		xio.RegisterUnlinkPath(cfg.LockWait)
		defer func() { _ = os.Remove(cfg.LockWait) }()
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

	g := &xio.Global{
		Log:          log,
		BlockSize:    cfg.BlockSize,
		Linger:       cfg.Linger,
		Verbose:      cfg.Verbose,
		Hex:          cfg.Hex,
		Dump:         os.Stderr,
		Statistics:   cfg.Statistics,
		Sloppy:       cfg.Sloppy,
		Experimental: cfg.Experimental,
		LeftToRight:  cfg.LeftToRight,
		RightToLeft:  cfg.RightToLeft,
	}
	g.EnsureStatsFlag()
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
		g.IPVersion = xio.IPvAny
	case cfg.IP6:
		g.IPVersion = xio.IPv6
	case cfg.IP4:
		g.IPVersion = xio.IPv4
	default:
		g.IPVersion = xio.IPv4Default
	}

	// Classic EXITCODESIG*: dying on SIGTERM/ILL/… exits with 128+signum.
	// Also unlink registered FS entries (UNIX/PIPE/PTY link) before Exit so
	// REMOVE* tests pass — os.Exit skips Opened.Close / SetUnlinkOnClose.
	sigCh := make(chan os.Signal, 1)
	notifyExitSignals(sigCh)
	defer signal.Stop(sigCh)
	usr1 := make(chan os.Signal, 1)
	notifyStatsSignal(usr1)
	defer signal.Stop(usr1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sig := <-sigCh
		cancel()
		xio.UnlinkRegisteredPaths()
		if ss, ok := sig.(syscall.Signal); ok && ss > 0 {
			// Exit immediately so Wait()-blocked nofork paths still report classic status.
			os.Exit(128 + int(ss))
		}
	}()
	go func() {
		for range usr1 {
			xio.PrintLiveStats(log)
		}
	}()

	runErr := xio.Run(ctx, left, right, g)
	if cfg.Statistics {
		xio.PrintExitStats(g)
	}
	if runErr != nil {
		if ctx.Err() != nil {
			if g.ChildExitCode != 0 {
				return g.ChildExitCode
			}
			return 0
		}
		// Classic socat exits 0 when accept-timeout fires with no peer.
		if runErr == xio.ErrAcceptTimeout {
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
	fprintf(w, "socat version %s on %s\n", socat.Version, time.Now().Format(time.RFC3339))
	fprintf(w, "   running on Go reimplementation (github.com/oittaa/socat)\n")
	fprintln(w, "features:")
	// Implemented = 1, not yet = 0. Keep names aligned with classic socat -V.
	feats := []struct {
		name string
		on   bool
	}{
		// Honesty: only set 1 for features that actually work end-to-end.
		{"HELP", true},
		{"STATS", true},
		{"STDIO", true},
		{"FDNUM", true},
		{"FILE", true},
		{"CREAT", true},
		{"GOPEN", true},
		{"TERMIOS", xio.FeatureTERMIOS},
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
		{"INTERFACE", true}, // Linux AF_PACKET SOCK_RAW
		{"TCP", true},
		{"UDP", true},
		{"SCTP", xio.FeatureSCTP},
		{"DCCP", false},
		{"UDPLITE", false},
		{"LISTEN", true},
		{"POSIXMQ", xio.FeaturePOSIXMQ},
		{"SOCKS4", true},
		{"SOCKS4A", true},
		{"SOCKS5", true},
		{"VSOCK", false},
		{"NAMESPACES", xio.FeatureNAMESPACES},
		{"PROXY", true},
		{"SYSTEM", true},
		{"SHELL", true},
		{"EXEC", true},
		{"READLINE", false},
		{"TUN", true}, // Linux /dev/net/tun
		{"PTY", true},
		{"TLS", true},     // stream TLS via crypto/tls (not DTLS)
		{"OPENSSL", true}, // alias of TLS (classic drop-in)
		{"FIPS", false},
		{"LIBWRAP", true},   // pure-Go hosts.allow/deny (no CGO libwrap)
		{"WEBSOCKET", true}, // WS/WSS via coder/websocket (not in classic socat)
		{"QUIC", true},      // RFC 9000 via quic-go (not HTTP/3; not in classic)
	}
	for _, f := range feats {
		if f.on {
			fprintf(w, "  #define WITH_%s 1\n", f.name)
		} else {
			fprintf(w, "  #undef WITH_%s\n", f.name)
		}
	}
}

func createLockFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) // #nosec G302 G304 -- -L lock file path comes from the user; 0644 matches classic socat
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("lockfile %s exists", path)
		}
		return err
	}
	_, werr := fmt.Fprintf(f, "%d\n", os.Getpid())
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(path)
		return werr
	}
	if cerr != nil {
		_ = os.Remove(path)
		return cerr
	}
	return nil
}

// Help and version writes: a failure is not actionable.
func fprintf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

func fprintln(w io.Writer, a ...any) {
	_, _ = fmt.Fprintln(w, a...)
}
