// Package cli implements the socat command-line interface.
package cli

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oittaa/socat"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/outbuf"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

// Config holds parsed global options.
type Config struct {
	Help          int // 0 none, 1 -h, 2 -hh, 3 -hhh
	Version       bool
	LogLevel      logx.Level
	LogFile       string
	Progname      string
	Micros        bool
	Hostname      bool
	Verbose       bool
	Hex           bool
	BlockSize     int
	Linger        time.Duration
	Idle          time.Duration // <0 infinite, 0 zero, >0 timeout
	IdleSet       bool
	LeftToRight   bool // -u
	RightToLeft   bool // -U
	IP4           bool
	IP6           bool
	IPAny         bool
	Statistics    bool
	Experimental  bool
	LockFile      string
	LockWait      string
	RawLeft       string // -r
	RawRight      string // -R
	SignalLogMask uint64 // -S: signals whose termination is logged
	Addresses     []string
}

// ParseArgs parses os.Args-style arguments (without program name).
func ParseArgs(args []string) (*Config, error) {
	cfg := &Config{
		LogLevel:      logx.Warning,
		BlockSize:     8192,
		Linger:        relay.DefaultLinger,
		Idle:          -1, // infinite
		Progname:      "socat",
		SignalLogMask: defaultSignalLogMask(),
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

// cliBoolFlags are exact-match switches that take no argument.
var cliBoolFlags = map[string]func(*Config){
	"-h":     func(cfg *Config) { cfg.Help = 1 },
	"-?":     func(cfg *Config) { cfg.Help = 1 },
	"--help": func(cfg *Config) { cfg.Help = 1 },
	"-hh":    func(cfg *Config) { cfg.Help = 2 },
	"-??":    func(cfg *Config) { cfg.Help = 2 },
	"-hhh":   func(cfg *Config) { cfg.Help = 3 },
	"-???":   func(cfg *Config) { cfg.Help = 3 },
	"-V":     func(cfg *Config) { cfg.Version = true },
	"-v":     func(cfg *Config) { cfg.Verbose = true },
	"-x":     func(cfg *Config) { cfg.Hex = true },
	"-s":     func(cfg *Config) {}, // classic -s; Go stream APIs have no portable subset of recoverable I/O errors
	"-u":     func(cfg *Config) { cfg.LeftToRight = true },
	"-U":     func(cfg *Config) { cfg.RightToLeft = true },
	"-4":     func(cfg *Config) { cfg.IP4 = true },
	"-6":     func(cfg *Config) { cfg.IP6 = true },
	"-0":     func(cfg *Config) { cfg.IPAny = true },
	"-lu":    func(cfg *Config) { cfg.Micros = true },
	"-lh":    func(cfg *Config) { cfg.Hostname = true },
	"-g":     func(cfg *Config) {}, // ignore option group check
	"-D":     func(cfg *Config) {}, // log FDs before transfer — future
	"-ls":    func(cfg *Config) {}, // log to stderr (default)
}

type cliValueFlag struct {
	key   string
	guard func(a string) bool
	set   func(cfg *Config, v string) error
}

// cliValueFlags take an argument attached to the flag or as the next argv
// entry. Order matters: first prefix match wins, mirroring the historical
// switch.
var cliValueFlags = []cliValueFlag{
	{"b", nil, setBlockSize},
	{"t", nil, setLingerFlag},
	{"T", nil, setIdleFlag},
	{"S", nil, setSignalLogMask},
	{"lp", nil, plainFlag((*Config).fieldProgname)},
	{"lf", nil, plainFlag((*Config).fieldLogFile)},
	{"L", nil, plainFlag((*Config).fieldLockFile)},
	{"W", nil, plainFlag((*Config).fieldLockWait)},
	{"r", func(a string) bool { return !strings.HasPrefix(a, "-reuse") }, plainFlag((*Config).fieldRawLeft)},
	{"R", nil, plainFlag((*Config).fieldRawRight)},
}

func setSignalLogMask(cfg *Config, value string) error {
	mask, err := strconv.ParseUint(strings.TrimSpace(value), 0, 64)
	if err != nil {
		return fmt.Errorf("invalid -S signal mask %q", value)
	}
	cfg.SignalLogMask = mask
	return nil
}

// plainFlag stores the raw option value in a config field.
func plainFlag(dst func(*Config) *string) func(cfg *Config, v string) error {
	return func(cfg *Config, v string) error {
		*dst(cfg) = v
		return nil
	}
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
			cfg.LogLevel = levelFromN(len(a) - 1)
			return nil
		}
	}
	if set, ok := cliBoolFlags[a]; ok {
		set(cfg)
		return nil
	}
	for _, f := range cliValueFlags {
		matched := strings.HasPrefix(a, "-"+f.key)
		if matched && f.guard != nil && !f.guard(a) {
			matched = false
		}
		if matched {
			v, err := optArg(a, f.key, args, i)
			if err != nil {
				return err
			}
			return f.set(cfg, v)
		}
	}
	// Legacy catch: unrecognized -d combos (-dx) act as bare verbosity.
	if strings.HasPrefix(a, "-d") {
		cfg.LogLevel = logx.Notice
		return nil
	}
	return fmt.Errorf("unknown option %q", a)
}

func setBlockSize(cfg *Config, v string) error {
	// Classic: bare/missing -b → "missing numerical value of option "-b""
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
	// Cap at a practical size to avoid OOM.
	const practical = 256 * 1024 * 1024
	if n > practical {
		return fmt.Errorf("buffer size option (-b) to big")
	}
	cfg.BlockSize = int(n)
	return nil
}

func setLingerFlag(cfg *Config, v string) error {
	d, err := parseDuration(v)
	if err != nil {
		return fmt.Errorf("invalid -t value %q: %w", v, err)
	}
	cfg.Linger = d
	return nil
}

func setIdleFlag(cfg *Config, v string) error {
	d, err := parseDuration(v)
	if err != nil {
		return fmt.Errorf("invalid -T value %q: %w", v, err)
	}
	cfg.IdleSet = true
	cfg.Idle = d
	if cfg.Idle < 0 {
		cfg.Idle = -1
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

func parseDuration(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, fmt.Errorf("empty duration")
	}
	f, err := strconv.ParseFloat(v, 64)
	if err == nil {
		secondsLimit := float64(math.MaxInt64) / float64(time.Second)
		if math.IsNaN(f) || math.IsInf(f, 0) || f > secondsLimit || f < -secondsLimit {
			return 0, fmt.Errorf("duration out of range")
		}
		return time.Duration(f * float64(time.Second)), nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, err
	}
	return d, nil
}

// Field selectors for plainFlag.
func (c *Config) fieldProgname() *string { return &c.Progname }
func (c *Config) fieldLogFile() *string  { return &c.LogFile }
func (c *Config) fieldLockFile() *string { return &c.LockFile }
func (c *Config) fieldLockWait() *string { return &c.LockWait }
func (c *Config) fieldRawLeft() *string  { return &c.RawLeft }
func (c *Config) fieldRawRight() *string { return &c.RawRight }

// Run runs socat with the given args (excluding program name). signalExit is
// owned by cmd/socat so tests can exercise signal handling without terminating
// the test process.
func Run(args []string, signalExit func(int)) int {
	xio.WaitFromEnv("SOCAT_MAIN_WAIT")
	cfg, err := ParseArgs(args)
	if err != nil {
		return cliWriteErr("socat: %v\n", err)
	}

	if cfg.Version {
		if err := printVersion(os.Stdout); err != nil {
			return cliWriteErr("socat: %v\n", err)
		}
		return 0
	}
	if cfg.Help > 0 {
		if err := printHelp(os.Stdout, cfg.Help); err != nil {
			return cliWriteErr("socat: %v\n", err)
		}
		return 0
	}

	if len(cfg.Addresses) != 2 {
		_ = cliWriteErr("socat: exactly two addresses required (got %d)\n", len(cfg.Addresses))
		if err := printHelp(os.Stderr, 1); err != nil {
			return cliWriteErr("socat: %v\n", err)
		}
		return 1
	}

	log, closeLog, err := setupLogger(cfg)
	if err != nil {
		return cliWriteErr("socat: %v\n", err)
	}
	defer closeLog()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopSignals := installSignalHandling(ctx, cancel, log, cfg.SignalLogMask, signalExit)
	defer stopSignals()

	unlockFiles, err := acquireLockFiles(ctx, cfg)
	if err != nil {
		return cliWriteErr("socat: %v\n", err)
	}
	defer unlockFiles()

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
	if err := validateChannelOptions(left); err != nil {
		log.Errorf("parse left address: %s", err)
		return 1
	}
	if err := validateChannelOptions(right); err != nil {
		log.Errorf("parse right address: %s", err)
		return 1
	}

	g := buildGlobal(cfg, log)

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

// setupLogger builds the process logger from -l* options. The returned close
// releases the -lf log file after Run completes.
func setupLogger(cfg *Config) (*logx.Logger, func(), error) {
	log := logx.New()
	logx.SetDefault(log)
	log.SetLevel(cfg.LogLevel)
	log.SetProgname(cfg.Progname)
	log.SetMicros(cfg.Micros)
	if cfg.Hostname {
		h, ok := os.LookupEnv("HOSTNAME")
		if !ok {
			h, _ = os.Hostname()
		}
		log.SetHostname(h)
	}
	closeLog := func() {}
	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) // #nosec G302 -- -lf log file is meant to be readable
		if err != nil {
			return nil, nil, err
		}
		closeLog = func() { logx.CloseQuiet(f) }
		log.SetOutput(f)
	}
	return log, closeLog, nil
}

// acquireLockFiles creates the -L lock file and, after -W's poll-wait, the
// -W lock file. Acquire and identity-safe release are shared with address
// options lockfile=/waitlock= (internal/xio HoldLockFile).
func acquireLockFiles(ctx context.Context, cfg *Config) (func(), error) {
	var cleanups []func()
	add := func(path string, wait bool) error {
		release, err := xio.HoldLockFile(ctx, path, wait)
		if err != nil {
			return err
		}
		cleanups = append(cleanups, release)
		return nil
	}
	fail := func(err error) (func(), error) {
		for _, c := range cleanups {
			c()
		}
		return nil, err
	}
	if cfg.LockFile != "" {
		if err := add(cfg.LockFile, false); err != nil {
			return fail(err)
		}
	}
	if cfg.LockWait != "" {
		if err := add(cfg.LockWait, true); err != nil {
			return fail(err)
		}
	}
	return func() {
		for _, c := range cleanups {
			c()
		}
	}, nil
}

// buildGlobal maps parsed flags onto the transfer-time Global.
func buildGlobal(cfg *Config, log *logx.Logger) *xio.Global {
	g := &xio.Global{
		Log:          log,
		BlockSize:    cfg.BlockSize,
		Linger:       cfg.Linger,
		Verbose:      cfg.Verbose,
		Hex:          cfg.Hex,
		Dump:         os.Stderr,
		Statistics:   cfg.Statistics,
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
	g.IPVersion = ipVersionFromFlags(cfg)
	return g
}

// ipVersionFromFlags resolves explicit -4/-6/-0 against the default
// (env SOCAT_DEFAULT_LISTEN_IP may still apply to listen paths).
func ipVersionFromFlags(cfg *Config) xio.IPVersion {
	switch {
	case cfg.IPAny:
		return xio.IPvAny
	case cfg.IP6:
		return xio.IPv6
	case cfg.IP4:
		return xio.IPv4
	default:
		return xio.IPv4Default
	}
}

// installSignalHandling wires the two classic signal behaviors: exit signals
// cancel the context, unlink registered FS entries and exit 128+signum
// (EXITCODESIG*), and SIGUSR1 prints live transfer statistics. The returned
// stop releases both signal channels.
func installSignalHandling(ctx context.Context, cancel context.CancelFunc, log *logx.Logger, signalLogMask uint64, signalExit func(int)) func() {
	sigCh := make(chan os.Signal, 1)
	notifyExitSignals(sigCh, signalLogMask)
	usr1 := make(chan os.Signal, 1)
	notifyStatsSignal(usr1)
	stopHandlers := startSignalHandlers(ctx, cancel, log, signalLogMask, signalExit, sigCh, usr1)
	return func() {
		signal.Stop(sigCh)
		signal.Stop(usr1)
		stopHandlers()
	}
}

func startSignalHandlers(ctx context.Context, cancel context.CancelFunc, log *logx.Logger, signalLogMask uint64, signalExit func(int), sigCh, usr1 <-chan os.Signal) func() {
	done := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		select {
		case sig := <-sigCh:
			cancel()
			xio.UnlinkRegisteredPaths()
			if ss, ok := sig.(syscall.Signal); ok && ss > 0 {
				if int(ss) < 64 && signalLogMask&(uint64(1)<<uint(ss)) != 0 && log != nil {
					// Classic logs ordinary termination signals below Error;
					// CHILDREN_SHUTUP checks must not mistake parent SIGTERM cleanup
					// for a child connection failure.
					log.Warningf("exiting on signal %d", ss)
				}
				// Exit immediately so Wait()-blocked nofork paths still report classic status.
				if signalExit != nil {
					signalExit(128 + int(ss))
				}
			}
		case <-ctx.Done():
		case <-done:
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-usr1:
				xio.PrintLiveStats(log)
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()
	return func() {
		once.Do(func() { close(done) })
		wg.Wait()
	}
}

func printVersion(w io.Writer) error {
	var b outbuf.Buf
	// Format compatible with classic test.sh testfeats() which greps:
	//   #define WITH_FOO 1
	b.Printf("socat version %s on %s\n", socat.Version, time.Now().Format(time.RFC3339))
	b.Printf("   running on Go reimplementation (github.com/oittaa/socat)\n")
	b.Println("features:")
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
		{"STALL", xio.FeatureSTALL},
		{"TEXT", true},
		{"SOCKETPAIR", xio.FeatureSOCKETPAIR},
		{"UNIX", true},
		// Go-specific detail flags. Classic only exposes the coarser WITH_UNIX.
		{"UNIX_DGRAM", xio.FeatureUNIXDatagram},
		{"UNIX_SEQPACKET", xio.FeatureUNIXSeqpacket},
		{"ABSTRACT_UNIXSOCKET", xio.FeatureABSTRACT},
		{"IP4", true},
		{"IP6", true},
		{"RAWIP", xio.FeatureRAWIP},
		{"GENERICSOCKET", xio.FeatureGENERICSOCKET},
		{"INTERFACE", xio.FeatureINTERFACE},
		{"TCP", true},
		{"UDP", true},
		{"SCTP", xio.FeatureSCTP},
		{"DCCP", false},
		{"UDPLITE", xio.FeatureUDPLITE},
		{"LISTEN", true},
		{"POSIXMQ", xio.FeaturePOSIXMQ},
		{"SOCKS4", true},
		{"SOCKS4A", true},
		{"SOCKS5", true},
		{"VSOCK", xio.FeatureVSOCK},
		{"NAMESPACES", xio.FeatureNAMESPACES},
		{"PROXY", true},
		{"SYSTEM", xio.FeatureEXEC},
		{"SHELL", xio.FeatureEXEC},
		{"EXEC", xio.FeatureEXEC},
		{"READLINE", false},
		{"TUN", xio.FeatureTUN},
		{"PTY", xio.FeaturePTY},
		{"TLS", true},     // stream TLS via crypto/tls (not DTLS)
		{"OPENSSL", true}, // alias of TLS (classic drop-in)
		{"FIPS", false},
		{"LIBWRAP", true},   // pure-Go hosts.allow/deny (no CGO libwrap)
		{"WEBSOCKET", true}, // WS/WSS via coder/websocket (not in classic socat)
		{"QUIC", true},      // RFC 9000 via quic-go (not HTTP/3; not in classic)
	}
	for _, f := range feats {
		if f.on {
			b.Printf("  #define WITH_%s 1\n", f.name)
		} else {
			b.Printf("  #undef WITH_%s\n", f.name)
		}
	}
	return b.Flush(w)
}

func cliWriteErr(format string, a ...any) int {
	if _, err := fmt.Fprintf(os.Stderr, format, a...); err != nil {
		return 1
	}
	return 1
}
