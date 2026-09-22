package xio_test

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

// boolOptions is every option decoded with parseBool, each on one address
// that accepts it. Integer flags (keepalive, so-debug, …) are not in this list.
var boolOptions = []struct {
	addr string
	name string
}{
	{"TCP:127.0.0.1:9", "fork"},
	{"TCP:127.0.0.1:9", "forever"},
	{"TCP:127.0.0.1:9", "ignoreeof"},
	{"TCP:127.0.0.1:9", "null-eof"},
	{"TCP:127.0.0.1:9", "end-close"},
	{"TCP:127.0.0.1:9", "crorlf"},
	{"TCP:127.0.0.1:9", "shut-none"},
	{"TCP:127.0.0.1:9", "shut-down"},
	{"TCP:127.0.0.1:9", "shut-close"},
	{"TCP:127.0.0.1:9", "shut-null"},
	{"TCP:127.0.0.1:9", "res-usevc"},
	{"TCP:127.0.0.1:9", "ai-addrconfig"},
	{"TCP:127.0.0.1:9", "ai-passive"},
	{"TCP:127.0.0.1:9", "ai-v4mapped"},
	{"TCP:127.0.0.1:9", "ai-all"},
	{"TCP:127.0.0.1:9", "lowport"},
	{"TCP:127.0.0.1:9", "reuseaddr"},
	{"TCP:127.0.0.1:9", "ipv6-v6only"},
	{"TCP:127.0.0.1:9", "ip-transparent"},
	{"UDP4:127.0.0.1:9", "ip-multicast-loop"},
	{"UDP6:[::1]:9", "ipv6-multicast-loop"},
	{"OPEN:f", "rdonly"},
	{"OPEN:f", "wronly"},
	{"OPEN:f", "rdwr"},
	{"OPEN:f", "creat"},
	{"OPEN:f", "excl"},
	{"OPEN:f", "append"},
	{"OPEN:f", "trunc"},
	{"OPEN:f", "nonblock"},
	{"OPEN:f", "o-direct"},
	{"OPEN:f", "o-sync"},
	{"OPEN:f", "o-dsync"},
	{"OPEN:f", "o-rsync"},
	{"OPEN:f", "o-noctty"},
	{"OPEN:f", "o-nofollow"},
	{"OPEN:f", "o-directory"},
	{"OPEN:f", "o-largefile"},
	{"OPEN:f", "async"},
	{"OPEN:f", "cloexec"},
	{"OPEN:f", "o-noatime"},
	{"OPEN:f", "flock"},
	{"OPEN:f", "flock-nb"},
	{"OPEN:f", "flock-sh"},
	{"OPEN:f", "flock-sh-nb"},
	{"OPEN:f", "setlk"},
	{"OPEN:f", "setlkw"},
	{"OPEN:f", "setlk-rd"},
	{"OPEN:f", "setlkw-rd"},
	{"OPEN:f", "fs-secrm"},
	{"OPEN:f", "fs-unrm"},
	{"OPEN:f", "fs-compr"},
	{"OPEN:f", "fs-sync"},
	{"OPEN:f", "fs-immutable"},
	{"OPEN:f", "fs-append"},
	{"OPEN:f", "fs-nodump"},
	{"OPEN:f", "fs-noatime"},
	{"OPEN:f", "fs-journal-data"},
	{"OPEN:f", "fs-notail"},
	{"OPEN:f", "fs-dirsync"},
	{"OPEN:f", "fs-topdir"},
	{"OPEN:f", "unlink"},
	{"OPEN:f", "unlink-early"},
	{"OPEN:f", "unlink-late"},
	{"OPEN:f", "unlink-close"},
	{"OPEN:f", "binary"},
	{"OPEN:f", "text"},
	{"OPEN:f", "noinherit"},
	{"EXEC:true", "nofork"},
	{"EXEC:true", "pipes"},
	{"EXEC:true", "pty"},
	{"EXEC:true", "ptmx"},
	{"EXEC:true", "openpty"},
	{"EXEC:true", "stderr"},
	{"EXEC:true", "setsid"},
	{"EXEC:true", "dash"},
	{"PTY", "pty-wait-slave"},
	{"PTY", "ctty"},
	{"PTY", "ignbrk"},
	{"PTY", "brkint"},
	{"PTY", "ignpar"},
	{"PTY", "parmrk"},
	{"PTY", "inpck"},
	{"PTY", "istrip"},
	{"PTY", "inlcr"},
	{"PTY", "igncr"},
	{"PTY", "icrnl"},
	{"PTY", "ixon"},
	{"PTY", "ixoff"},
	{"PTY", "ixany"},
	{"PTY", "imaxbel"},
	{"PTY", "opost"},
	{"PTY", "onlcr"},
	{"PTY", "ocrnl"},
	{"PTY", "onocr"},
	{"PTY", "onlret"},
	{"PTY", "cstopb"},
	{"PTY", "cread"},
	{"PTY", "parenb"},
	{"PTY", "parodd"},
	{"PTY", "hupcl"},
	{"PTY", "clocal"},
	{"PTY", "crtscts"},
	{"PTY", "isig"},
	{"PTY", "icanon"},
	{"PTY", "echo"},
	{"PTY", "echoe"},
	{"PTY", "echok"},
	{"PTY", "echonl"},
	{"PTY", "noflsh"},
	{"PTY", "tostop"},
	{"PTY", "echoctl"},
	{"PTY", "echoke"},
	{"PTY", "iexten"},
	{"PTY", "iuclc"},
	{"PTY", "olcuc"},
	{"PTY", "xcase"},
	{"PTY", "pendin"},
	{"PTY", "echoprt"},
	{"PTY", "flusho"},
	{"PTY", "ofill"},
	{"PTY", "ofdel"},
	{"PTY", "nldly"},
	{"PTY", "bsdly"},
	{"PTY", "vtdly"},
	{"PTY", "ffdly"},
	{"UNIX-CONNECT:sock", "unix-tightsocklen"},
	{"OPENSSL:127.0.0.1:1", "verify"},
	{"OPENSSL:127.0.0.1:1", "nosni"},
	{"OPENSSL:127.0.0.1:1", "openssl-fips"},
	{"OPENSSL:127.0.0.1:1", "openssl-pseudo"},
	{"PROXY:127.0.0.1:127.0.0.1:9", "h2c"},
	{"PROXY:127.0.0.1:127.0.0.1:9", "ignorecr"},
	{"PROXY:127.0.0.1:127.0.0.1:9", "proxy-resolve"},
	{"DTLS:127.0.0.1:1", "dtls-migration"},
	{"DTLS:127.0.0.1:1", "dtls-unfragmented-probes"},
	{"TUN", "iff-no-pi"},
	{"TUN", "iff-up"},
	{"TUN", "iff-broadcast"},
	{"TUN", "iff-debug"},
	{"TUN", "iff-loopback"},
	{"TUN", "iff-pointopoint"},
	{"TUN", "iff-notrailers"},
	{"TUN", "iff-running"},
	{"TUN", "iff-noarp"},
	{"TUN", "iff-promisc"},
	{"TUN", "iff-allmulti"},
	{"TUN", "iff-master"},
	{"TUN", "iff-slave"},
	{"TUN", "iff-multicast"},
	{"TUN", "iff-portsel"},
	{"TUN", "iff-automedia"},
	{"POSIXMQ-SEND:/q", "mq-flush"},
}

func TestBoolOptionGrammar(t *testing.T) {
	seen := map[string]string{}
	for _, opt := range boolOptions {
		if prev, ok := seen[opt.name]; ok {
			t.Fatalf("duplicate bool option %s on %s and %s", opt.name, prev, opt.addr)
		}
		seen[opt.name] = opt.addr
	}
	accepts := []string{"0", "1", "yes", "no", "true", "false", "YES", "False"}
	rejects := []string{"2", "on", "off", "00", "bogus", ""}
	const wantForms = "want 0, 1, yes, no, true, or false"
	for _, opt := range boolOptions {
		for _, value := range accepts {
			spec := opt.addr + "," + opt.name + "=" + value
			err := prepareBool(t, spec)
			if !boolValueAccepted(err) {
				t.Errorf("%s: %v", spec, err)
			}
		}
		if opt.name == "reuseaddr" {
			err := prepareBool(t, opt.addr+",reuseaddr=")
			if err != nil {
				t.Errorf("%s,reuseaddr=: %v", opt.addr, err)
			}
		}
		for _, value := range rejects {
			if opt.name == "reuseaddr" && value == "" {
				continue
			}
			spec := opt.addr + "," + opt.name + "=" + value
			err := prepareBool(t, spec)
			if err == nil || !strings.Contains(err.Error(), wantForms) {
				t.Errorf("%s: %v", spec, err)
			}
		}
	}
}

func TestIntegerFlagGrammar(t *testing.T) {
	for _, spec := range []string{
		"TCP:127.0.0.1:9,keepalive=2",
		"TCP:127.0.0.1:9,keepalive=00",
		"TCP:127.0.0.1:9,reuseport=0x2",
		"TCP:127.0.0.1:9,nodelay=yes",
		"TCP:127.0.0.1:9,so-debug=yes",
		"TCP:127.0.0.1:9,so-dontroute=no",
		"TCP:127.0.0.1:9,so-oobinline=true",
		"TCP:127.0.0.1:9,broadcast=7",
		"TCP:127.0.0.1:9,tcp-cork=false",
		"TCP:127.0.0.1:9,ip-freebind=1",
		"TCP:127.0.0.1:9,ip-ttl=2",
		"TCP:127.0.0.1:9,ip-ttl=no",
		"UDP4:127.0.0.1:9,mcloop=yes",
		"UDP6:[::1]:9,mcloop6=no",
		"TCP:127.0.0.1:9,transparent=yes",
	} {
		if err := prepareBool(t, spec); err != nil {
			t.Errorf("%s: %v", spec, err)
		}
	}
	for _, spec := range []string{
		"TCP:127.0.0.1:9,keepalive=on",
		"TCP:127.0.0.1:9,so-debug=on",
		"TCP:127.0.0.1:9,broadcast=on",
		"TCP:127.0.0.1:9,ip-ttl=on",
	} {
		err := prepareBool(t, spec)
		if err == nil || !strings.Contains(err.Error(), "want an integer, or 0, 1, yes, no, true, or false") {
			t.Errorf("%s: %v", spec, err)
		}
	}
	for _, spec := range []string{
		"UDP4:127.0.0.1:9,ip-multicast-loop=00",
		"UDP4:127.0.0.1:9,ip-multicast-loop=0x1",
		"UDP6:[::1]:9,mcloop6=2",
		"TCP:127.0.0.1:9,ip-transparent=2",
		"TCP:127.0.0.1:9,ip-transparent=7",
	} {
		err := prepareBool(t, spec)
		if err == nil || !strings.Contains(err.Error(), "want 0, 1, yes, no, true, or false") || strings.Contains(err.Error(), "want an integer") {
			t.Errorf("%s: %v", spec, err)
		}
	}
}

func prepareBool(t *testing.T, spec string) error {
	t.Helper()
	parsed, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatalf("parse %s: %v", spec, err)
	}
	_, err = xio.PrepareSpec(parsed)
	return err
}

// boolValueAccepted reports a value that parsed as a boolean. A later
// platform rejection is not a grammar failure.
func boolValueAccepted(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, "want 0, 1, yes, no, true, or false") {
		return false
	}
	return strings.Contains(msg, "not supported on this platform")
}
