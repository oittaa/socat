package cli

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/classiccatalog"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestParseDurationRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{"", "banana", "NaN", "+Inf", "1e100"} {
		if _, err := parseDuration(value); err == nil {
			t.Errorf("parseDuration(%q) succeeded", value)
		}
	}
	for _, value := range []string{"1", "1.5", "250ms", "-1"} {
		if _, err := parseDuration(value); err != nil {
			t.Errorf("parseDuration(%q): %v", value, err)
		}
	}
}

func TestParseArgsRejectsMalformedTimeouts(t *testing.T) {
	for _, args := range [][]string{{"-tbanana"}, {"-Tbanana"}} {
		if _, err := ParseArgs(args); err == nil {
			t.Fatalf("ParseArgs(%q) succeeded", args)
		}
	}
}

func TestParseSignalLogMask(t *testing.T) {
	cfg, err := ParseArgs([]string{"-S", "0x80000000"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SignalLogMask != 0x80000000 {
		t.Fatalf("SignalLogMask=%#x", cfg.SignalLogMask)
	}
	if _, err := ParseArgs([]string{"-S", "not-a-mask"}); err == nil {
		t.Fatal("invalid -S mask was accepted")
	}
}

func TestValidateAddressOptions(t *testing.T) {
	tests := []struct {
		name       string
		spec       string
		wantErr    string
		windowsErr string
	}{
		{name: "create-excl", spec: "CREATE:file,excl", wantErr: "not supported"},
		{name: "open-excl", spec: "OPEN:file,excl"},
		{name: "unix-recvfrom-accept-timeout", spec: "UNIX-RECVFROM:sock,accept-timeout=0.1", wantErr: "not supported"},
		{name: "unix-recvfrom-range", spec: "UNIX-RECVFROM:sock,range=127.0.0.1/32", wantErr: "not supported"},
		{name: "udp-recvfrom-accept-timeout", spec: "UDP-RECVFROM:1,accept-timeout=0.1", wantErr: "not supported"},
		{name: "udp-listen-accept-timeout", spec: "UDP-LISTEN:1,accept-timeout=0.1"},
		{name: "udp-recvfrom-range", spec: "UDP-RECVFROM:1,range=127.0.0.1/32"},
		{name: "lowport-on-file", spec: "OPEN:file,lowport", wantErr: "not supported"},
		{name: "sourceport-on-file", spec: "OPEN:file,sourceport=1", wantErr: "not supported"},
		{name: "lowport-on-quic", spec: "QUIC:localhost:1,lowport"},
		{name: "sourceport-on-quic", spec: "QUIC:localhost:1,sourceport=1"},
		{name: "pty-on-tcp", spec: "TCP:localhost:1,pty", wantErr: "not supported"},
		{name: "echo-on-tcp", spec: "TCP:localhost:1,echo", wantErr: "not supported"},
		{name: "pipes-on-tcp", spec: "TCP:localhost:1,pipes", wantErr: "not supported"},
		{name: "fork-on-udp-connect", spec: "UDP:localhost:1,fork", wantErr: "not supported"},
		{name: "fork-on-tcp-connect", spec: "TCP:localhost:1,fork"},
		{name: "accept-timeout-on-tcp-listen", spec: "TCP-LISTEN:1,accept-timeout=0.1"},
		{name: "excl-on-tcp", spec: "TCP:localhost:1,excl", wantErr: "not supported"},
		{name: "unlink-close-on-tcp", spec: "TCP:localhost:1,unlink-close", wantErr: "not supported"},
		{name: "open-unlink", spec: "OPEN:file,unlink"},
		{name: "open-delete-alias", spec: "OPEN:file,delete"},
		{name: "open-remove-alias", spec: "OPEN:file,remove"},
		{name: "open-perm-early", spec: "OPEN:file,perm-early=0600"},
		{name: "open-user-early-alias", spec: "OPEN:file,uid-e=0"},
		{name: "open-group-early-alias", spec: "OPEN:file,gid-e=0"},
		{name: "bad-perm-early", spec: "OPEN:file,perm-early=xyz", wantErr: "invalid perm-early"},
		{name: "unlink-on-tcp", spec: "TCP:localhost:1,unlink", wantErr: "not supported"},
		{name: "setsid-on-tcp", spec: "TCP:localhost:1,setsid"},
		{name: "readbytes-on-tcp", spec: "TCP:localhost:1,readbytes=4"},
		{name: "path-on-exec", spec: "EXEC:true,path=/bin/true"},
		{name: "fork-on-exec", spec: "EXEC:true,fork", wantErr: "not supported"},
		{name: "known-alias", spec: "TCP-LISTEN:1,so-reuseaddr"},
		{name: "zero-socket-timeouts", spec: "UDP:localhost:1,rcvtimeo=0,sndtimeo=0"},
		{name: "socketpair-timeouts", spec: "SOCKETPAIR,rcvtimeo=0.1,sndtimeo=0.1"},
		{name: "interface-timeouts", spec: "INTERFACE:lo,rcvtimeo=0.1,sndtimeo=0.1"},
		{name: "tls-timeouts", spec: "TLS:localhost:1,rcvtimeo=0.1,sndtimeo=0.1"},
		{name: "listen-sockopt-alias", spec: "TCP-LISTEN:1,sockopt-listen=1:2:1"},
		{name: "openssl-cipher-alias", spec: "OPENSSL:localhost:443,cipher=ECDHE-ECDSA-AES256-GCM-SHA384"},
		{name: "proxy-tls-option", spec: "PROXY:localhost:example.com:443,verify=0"},
		{name: "classic-keepalive-aliases", spec: "TCP:localhost:1,tcp-keepidle=7,tcp-keepintvl=9,tcp-keepcnt=3"},
		{name: "classic-listen-timeout-alias", spec: "TCP-LISTEN:1,listen-timeout=0.1"},
		{name: "classic-ignoreof-alias", spec: "OPEN:file,ignoreof"},
		{name: "ipv6-join-group-on-tcp4", spec: "TCP4:localhost:1,ipv6-join-group=[ff02::2]:lo"},
		{name: "classic-linger-alias", spec: "TCP:localhost:1,linger=0"},
		{name: "sndbuf", spec: "TCP:localhost:1,sndbuf=4096"},
		{name: "rcvbuf-alias", spec: "TCP:localhost:1,so-rcvbuf=8192"},
		{name: "sndbuf-late-alias", spec: "TCP:localhost:1,so-sndbuf-late=4096"},
		{name: "rcvbuf-late", spec: "UDP:localhost:1,rcvbuf-late=8192"},
		{name: "bindtodevice-if", spec: "TCP-LISTEN:1,if=lo"},
		{name: "bindtodevice-so", spec: "UDP:localhost:1,so-bindtodevice=lo"},
		{name: "bindtodevice-interface", spec: "TCP4:localhost:1,interface=lo"},
		{name: "zero-sndbuf", spec: "TCP:localhost:1,sndbuf=0"},
		{name: "socketpair-sndbuf", spec: "SOCKETPAIR,sndbuf=4096,sndbuf-late=8192"},
		{name: "children-shutup-bare", spec: "TCP-LISTEN:1,fork,children-shutup"},
		{name: "linux-fd-options", spec: "STDIN,o-noatime,f-setpipe-sz=4096"},
		{name: "noatime-on-tcp", spec: "TCP:localhost:1,noatime"},
		{name: "o-direct-on-open", spec: "OPEN:file,o-direct"},
		{name: "o-direct-alias", spec: "FILE:file,direct"},
		{name: "o-direct-underscore", spec: "GOPEN:file,o_direct"},
		{name: "o-direct-on-create", spec: "CREATE:file,o-direct", wantErr: "not supported"},
		{name: "o-direct-on-pipe", spec: "PIPE:file,o-direct"},
		{name: "o-direct-on-fifo", spec: "FIFO:file,o-direct"},
		{name: "o-direct-on-tcp", spec: "TCP:localhost:1,o-direct", wantErr: "not supported"},
		{name: "o-direct-on-fd", spec: "FD:3,o-direct", wantErr: "not supported"},
		{name: "fs-noatime-on-open", spec: "OPEN:file,fs-noatime"},
		{name: "fs-noatime-on-create", spec: "CREATE:file,fs-noatime"},
		{name: "ext2-noatime-alias", spec: "OPEN:file,ext2-noatime"},
		{name: "ext3-noatime-alias", spec: "FD:3,ext3-noatime"},
		{name: "fs-noatime-on-tcp", spec: "TCP:localhost:1,fs-noatime", wantErr: "not supported"},
		{name: "fs-noatime-on-pipe", spec: "PIPE:file,fs-noatime", wantErr: "not supported"},
		{name: "vsock-connect-bind", spec: "VSOCK-CONNECT:1:9,bind=:5555"},
		{name: "vsock-listen-fork", spec: "VSOCK-LISTEN:9,fork,reuseaddr,backlog=16"},
		{name: "vsock-sndbuf", spec: "VSOCK-CONNECT:1:9,sndbuf=4096,connect-timeout=1"},
		{name: "vsock-pf-inet", spec: "VSOCK-LISTEN:9,pf=inet"},
		{name: "vsock-protocol-family", spec: "VSOCK-LISTEN:9,protocol-family=inet"},
		{name: "vsock-so-protocol", spec: "VSOCK-LISTEN:9,so-protocol=6"},
		{name: "vsock-so-prototype", spec: "VSOCK-LISTEN:9,so-prototype=6"},
		{name: "vsock-protocol", spec: "VSOCK-LISTEN:9,protocol=6"},
		{name: "vsock-type", spec: "VSOCK-LISTEN:9,type=3"},
		{name: "tcp-so-protocol-not-implemented", spec: "TCP:localhost:1,so-protocol=6", wantErr: "not supported"},
		{name: "tcp-protocol-not-implemented", spec: "TCP:localhost:1,protocol=6", wantErr: "not supported"},
		{name: "websocket-protocol", spec: "WS:localhost:1,protocol=chat"},
		{name: "vsock-range", spec: "VSOCK-LISTEN:9,range=127.0.0.1/32", wantErr: "not supported"},
		{name: "vsock-sourceport", spec: "VSOCK-CONNECT:1:9,sourceport=1", wantErr: "not supported"},
		{name: "fs-noatime-on-exec", spec: "EXEC:true,fs-noatime", wantErr: "not supported"},
		{name: "pktinfo-on-udp4", spec: "UDP4:localhost:1,pktinfo", windowsErr: "not supported on this platform"},
		{name: "pktinfo-on-udp-connect", spec: "UDP-CONNECT:localhost:1,ip-pktinfo", windowsErr: "not supported on this platform"},
		{name: "pktinfo-on-tcp", spec: "TCP:localhost:1,ip-pktinfo", wantErr: "not supported"},
		{name: "timestamp-on-tcp", spec: "TCP:localhost:1,so-timestamp", wantErr: "not supported"},
		{name: "recvttl-on-quic", spec: "QUIC:localhost:1,ip-recvttl", wantErr: "not supported"},
		{name: "pktinfo-on-unix", spec: "UNIX-CONNECT:sock,ip-pktinfo", wantErr: "not supported"},
		{name: "timestamp-on-unix", spec: "UNIX-CONNECT:sock,so-timestamp", wantErr: "not supported"},
		{name: "ttl-on-quic", spec: "QUIC:localhost:1,ip-ttl=9"},
		{name: "ttl-on-tcp", spec: "TCP:localhost:1,ip-ttl=9"},
		{name: "ttl-on-tcp6", spec: "TCP6:localhost:1,ip-ttl=9"},
		{name: "tos-on-tcp6", spec: "TCP6:localhost:1,ip-tos=16"},
		{name: "tclass-on-tcp4", spec: "TCP4:localhost:1,ipv6-tclass=16", wantErr: "not supported on IPv4", windowsErr: "not supported on this platform"},
		{name: "unicast-hops-on-tcp4", spec: "TCP4:localhost:1,ipv6-unicast-hops=9", wantErr: "not supported on IPv4", windowsErr: "not supported on this platform"},
		{name: "tclass-on-tcp6", spec: "TCP6:localhost:1,ipv6-tclass=16", windowsErr: "not supported on this platform"},
		{name: "pktinfo-on-udp6", spec: "UDP6:localhost:1,ip-pktinfo", wantErr: "not supported on IPv6", windowsErr: "not supported on this platform"},
		{name: "recvhoplimit-on-udp4", spec: "UDP4:localhost:1,ipv6-recvhoplimit", wantErr: "not supported on IPv4", windowsErr: "not supported on this platform"},
		{name: "concat-ippktinfo", spec: "UDP4:localhost:1,ippktinfo", windowsErr: "not supported on this platform"},
		{name: "recvttl-alias-last-wins", spec: "UDP4:localhost:1,ip-recvttl=1,recvttl=0", windowsErr: "not supported on this platform"},
		{name: "classic-ip-aliases", spec: "TCP:localhost:1,ipttl=9,iptos=16"},
		{name: "tls-version-bounds", spec: "TLS:localhost:443,min-version=TLS1.2,max-version=TLS1.3"},
		{name: "tcp-options-on-wss", spec: "WSS:localhost:1,nodelay,keepalive"},
		{name: "tls-options-on-wss", spec: "WSS:localhost:1,verify=0"},
		{name: "alpn-on-quic", spec: "QUIC:localhost:1,alpn=socat"},
		{name: "wrong-tls-family", spec: "OPEN:file,verify=0", wantErr: "not supported"},
		{name: "tls-option-on-plain-websocket", spec: "WS:localhost:1,cert=cert.pem", wantErr: "not supported"},
		{name: "tls-option-on-socks", spec: "SOCKS5:localhost:example.com:443,verify=0", wantErr: "not supported"},
		{name: "alpn-on-tls", spec: "TLS:localhost:443,alpn=h2", wantErr: "not supported"},
		{name: "wrong-websocket-family", spec: "TCP:localhost:1,path=/socket", wantErr: "not supported"},
		{name: "path-on-ws", spec: "WS:localhost:1,path=/socket"},
		{name: "wrong-proxy-family", spec: "UDP:localhost:1,socksuser=user", wantErr: "not supported"},
		{name: "proxy-option-on-socks", spec: "SOCKS4:localhost:example.com:80,proxyport=8080", wantErr: "not supported"},
		{name: "socks-option-on-proxy", spec: "PROXY:localhost:example.com:80,socksuser=user", wantErr: "not supported"},
		{name: "backlog-on-tcp", spec: "TCP-LISTEN:1,backlog=10"},
		{name: "hex-max-children", spec: "TCP-LISTEN:1,fork,max-children=0x10"},
		{name: "octal-max-children", spec: "TCP-LISTEN:1,fork,max-children=010"},
		{name: "octal-ftruncate", spec: "OPEN:file,ftruncate=010"},
		{name: "backlog-on-socket", spec: "SOCKET-LISTEN:2:0:x00,backlog=10"},
		{name: "nodelay-on-file", spec: "CREATE:file,nodelay", wantErr: "not supported"},
		{name: "keepalive-on-udp", spec: "UDP:localhost:1,keepalive"},
		{name: "nodelay-on-udp", spec: "UDP:localhost:1,nodelay", wantErr: "not supported"},
		{name: "append-on-tcp", spec: "TCP:localhost:1,append"},
		{name: "socket-timeout-on-file", spec: "OPEN:file,rcvtimeo=0.1", wantErr: "not supported"},
		{name: "socket-timeout-on-fifo", spec: "FIFO:file,sndtimeo=0.1", wantErr: "not supported"},
		{name: "socket-timeout-on-pty", spec: "PTY,rcvtimeo=0.1", wantErr: "not supported"},
		{name: "socket-timeout-on-tun", spec: "TUN,rcvtimeo=0.1", wantErr: "not supported"},
		{name: "socket-timeout-on-websocket", spec: "WS:localhost:1,rcvtimeo=0.1"},
		{name: "socket-timeout-on-quic", spec: "QUIC:localhost:1,sndtimeo=0.1"},
		{name: "wrong-mq-family", spec: "TCP:localhost:1,mq-prio=1", wantErr: "not supported"},
		{name: "wrong-tun-family", spec: "CREATE:file,tun-name=tun0", wantErr: "not supported"},
		{name: "unknown", spec: "CREATE:file,totally-unknown=1", wantErr: "unknown option"},
		{name: "bad-perm", spec: "CREATE:file,perm=xyz", wantErr: "invalid perm"},
		{name: "readbytes-hex", spec: "OPEN:file,readbytes=0x10"},
		{name: "readbytes-octal", spec: "OPEN:file,readbytes=010"},
		{name: "readbytes-zero", spec: "OPEN:file,readbytes=0"},
		{name: "readbytes-negative", spec: "OPEN:file,readbytes=-1"},
		{name: "bad-duration", spec: "TCP:localhost:1,connect-timeout=soon", wantErr: "invalid connect-timeout"},
		{name: "negative-socket-timeout", spec: "UDP:localhost:1,rcvtimeo=-1", wantErr: "invalid rcvtimeo"},
		{name: "bad-children", spec: "TCP-LISTEN:1,fork,max-children=many", wantErr: "invalid max-children"},
		{name: "zero-keepcnt", spec: "TCP:localhost:1,keepcnt=0", wantErr: "invalid keepcnt"},
		{name: "bad-socktype", spec: "UNIX:file,socktype=stream", wantErr: "invalid socktype"},
		{name: "bad-ftruncate", spec: "OPEN:file,ftruncate=-1", wantErr: "invalid ftruncate"},
		{name: "bad-listen-sockopt-fields", spec: "TCP-LISTEN:1,setsockopt-listen=1:2", wantErr: "level:optname:value"},
		{name: "bad-listen-sockopt-number", spec: "TCP-LISTEN:1,setsockopt-listen=1:name:1", wantErr: "integer"},
		{name: "missing-ciphers", spec: "TLS:localhost:443,ciphers", wantErr: "requires a value"},
		{name: "missing-ip-options", spec: "UDP:localhost:1,ip-options", wantErr: "requires a value"},
		{name: "missing-linger", spec: "TCP:localhost:1,so-linger", wantErr: "requires a value"},
		{name: "missing-sndbuf", spec: "TCP:localhost:1,sndbuf", wantErr: "requires a value"},
		{name: "negative-sndbuf", spec: "TCP:localhost:1,sndbuf=-1", wantErr: "invalid sndbuf"},
		{name: "negative-rcvbuf-late", spec: "TCP:localhost:1,rcvbuf-late=-1", wantErr: "invalid rcvbuf-late"},
		{name: "missing-bindtodevice", spec: "TCP:localhost:1,bindtodevice", wantErr: "requires a value"},
		{name: "empty-bindtodevice", spec: "TCP:localhost:1,if=", wantErr: "requires a value"},
		{name: "sndbuf-on-file", spec: "OPEN:file,sndbuf=4096", wantErr: "not supported"},
		{name: "bindtodevice-on-file", spec: "OPEN:file,bindtodevice=lo", wantErr: "not supported"},
		{name: "bad-pipe-size", spec: "STDIN,f-setpipe-sz=0", wantErr: "invalid f-setpipe-sz"},
		{name: "missing-min-version", spec: "TLS:localhost:443,min-version", wantErr: "requires a value"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch, err := parse.ParseChannel(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			err = validateChannelOptions(ch)
			wantErr := tc.wantErr
			if runtime.GOOS == "windows" && tc.windowsErr != "" {
				wantErr = tc.windowsErr
			}
			if wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), wantErr) {
				t.Fatalf("error=%v want substring %q", err, wantErr)
			}
		})
	}
}

func TestAddressDurationUsesCLIUnits(t *testing.T) {
	o := parse.Option{Name: "connect-timeout", Value: "0.25", Has: true}
	if err := validateAddressOptionValue(o); err != nil {
		t.Fatal(err)
	}
	d, err := parseDuration(o.Value)
	if err != nil || d != 250*time.Millisecond {
		t.Fatalf("duration=%v err=%v", d, err)
	}
}

func TestWinsizeHelpUsesColumnRowOrder(t *testing.T) {
	for _, group := range helpOptionGroups() {
		for _, option := range group.opts {
			if option.name == "tiocswinsz" {
				if option.desc != "window size cols:rows" {
					t.Fatalf("tiocswinsz description=%q", option.desc)
				}
				return
			}
		}
	}
	t.Fatal("tiocswinsz missing from help options")
}

func TestReuseaddrHelpMentionsTCPDefaultAndUDPFork(t *testing.T) {
	for _, group := range helpOptionGroups() {
		for _, option := range group.opts {
			if option.name == "reuseaddr" {
				if !strings.Contains(option.desc, "TCP") || !strings.Contains(option.desc, "UDP-LISTEN") {
					t.Fatalf("reuseaddr description=%q", option.desc)
				}
				return
			}
		}
	}
	t.Fatal("reuseaddr missing from help options")
}

func TestBroadcastHelpAdvertisesSoBroadcast(t *testing.T) {
	for _, group := range helpOptionGroups() {
		for _, option := range group.opts {
			if option.name != "broadcast" {
				continue
			}
			for _, alias := range option.aliases {
				if alias == "so-broadcast" {
					return
				}
			}
			t.Fatalf("broadcast aliases=%v want so-broadcast", option.aliases)
		}
	}
	t.Fatal("broadcast missing from help options")
}

func TestHelpDoesNotAdvertiseCoolWrite(t *testing.T) {
	for _, group := range helpOptionGroups() {
		for _, option := range group.opts {
			if option.name == "cool-write" {
				t.Fatal("cool-write must not be advertised")
			}
			for _, alias := range option.aliases {
				if alias == "cool-write" {
					t.Fatal("cool-write must not be advertised as an alias")
				}
			}
		}
	}
}

func TestHelpOptionGroupOrder(t *testing.T) {
	var titles []string
	for _, group := range helpOptionGroups() {
		titles = append(titles, group.title)
	}
	want := []string{
		"Listen and connect",
		"Security filters",
		"Sockets",
		"Files and UNIX",
		"EXEC, SYSTEM, SHELL",
		"PTY and TERMIOS",
		"Transfer",
		"TLS, WSS, and QUIC",
		"WebSocket",
		"PROXY and SOCKS",
		"POSIX message queues",
		"TUN and INTERFACE",
		"Namespaces",
	}
	if strings.Join(titles, ",") != strings.Join(want, ",") {
		t.Fatalf("help group order=%v want %v", titles, want)
	}
}

func TestCatalogLifecyclePhasesForAdvertisedFDOptions(t *testing.T) {
	tests := []struct {
		spelling string
		phase    string
		groups   []string
	}{
		{spelling: "append", phase: "LATE", groups: []string{"FD", "OPEN"}},
		{spelling: "o-append", phase: "LATE", groups: []string{"FD", "OPEN"}},
		{spelling: "ftruncate", phase: "LATE", groups: []string{"REG"}},
		{spelling: "perm", phase: "FD", groups: []string{"FD", "NAMED"}},
		{spelling: "user", phase: "FD", groups: []string{"FD", "NAMED"}},
		{spelling: "group", phase: "FD", groups: []string{"FD", "NAMED"}},
	}
	for _, tt := range tests {
		e, ok := classiccatalog.Lookup(tt.spelling)
		if !ok {
			t.Errorf("%q missing from classic catalog", tt.spelling)
			continue
		}
		if e.Phase != tt.phase {
			t.Errorf("%q phase=%q want %q", tt.spelling, e.Phase, tt.phase)
		}
		if strings.Join(e.Groups, ",") != strings.Join(tt.groups, ",") {
			t.Errorf("%q groups=%v want %v", tt.spelling, e.Groups, tt.groups)
		}
	}
}

func TestIPAncillaryMatrixWiredIntoCLI(t *testing.T) {
	table := buildSupportedAddressOptions()
	for _, name := range xio.IPAncillaryNames() {
		got, ok := table[name]
		if !ok {
			t.Errorf("matrix option %q missing from CLI table", name)
			continue
		}
		want := xio.IPAncillaryImplementationGroups(name)
		if strings.Join(got.implementationGroups, ",") != strings.Join(want, ",") {
			t.Errorf("%q implementationGroups=%v want %v", name, got.implementationGroups, want)
		}
	}
}
