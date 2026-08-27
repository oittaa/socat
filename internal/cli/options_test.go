package cli

import (
	"reflect"
	"sort"
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
		name    string
		spec    string
		wantErr string
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
		{name: "setsockopt-int", spec: "TCP:localhost:1,setsockopt-int=1:9:1"},
		{name: "sockopt-int-alias", spec: "TCP:localhost:1,sockopt-int=1:9:1"},
		{name: "setsockopt-bin-hex", spec: "TCP:localhost:1,setsockopt-bin=1:9:x01000000"},
		{name: "setsockopt-bin-garbage", spec: "TCP:localhost:1,setsockopt-bin=1:9:not-a-dalan-path", wantErr: "invalid setsockopt-bin"},
		{name: "setsockopt-bin-leftover", spec: "TCP:localhost:1,setsockopt-bin=1:9:512junk", wantErr: "invalid setsockopt-bin"},
		{name: "sockopt-bin-alias", spec: "UDP:localhost:1,sockopt-bin=1:9:1"},
		{name: "setsockopt-string", spec: "TCP:localhost:1,setsockopt-string=1:1:lo"},
		{name: "sockopt-string-alias", spec: "TCP:localhost:1,sockopt-string=1:1:lo"},
		{name: "setsockopt-socket", spec: "TCP-LISTEN:1,setsockopt-socket=1:9:1"},
		{name: "sockopt-sock-alias", spec: "TCP-LISTEN:1,sockopt-sock=1:9:1"},
		{name: "setsockopt-connected", spec: "TCP:localhost:1,setsockopt-connected=1:9:1"},
		{name: "sockopt-conn-alias", spec: "TCP:localhost:1,sockopt-conn=1:9:1"},
		{name: "sockopt-alias", spec: "TCP:localhost:1,sockopt=1:9:1"},
		{name: "openssl-cipher-alias", spec: "OPENSSL:localhost:443,cipher=ECDHE-ECDSA-AES256-GCM-SHA384"},
		{name: "proxy-tls-option", spec: "PROXY:localhost:example.com:443,verify=0"},
		{name: "classic-keepalive-aliases", spec: "TCP:localhost:1,tcp-keepidle=7,tcp-keepintvl=9,tcp-keepcnt=3"},
		{name: "classic-listen-timeout-alias", spec: "TCP-LISTEN:1,listen-timeout=0.1"},
		{name: "classic-ignoreof-alias", spec: "OPEN:file,ignoreof"},
		{name: "ipv6-join-group-on-tcp4", spec: "TCP4:localhost:1,ipv6-join-group=[ff02::2]:lo", wantErr: "not supported"},
		{name: "ipv6-join-group-on-udp4-recv", spec: "UDP4-RECV:1,ipv6-join-group=[ff02::2]:lo", wantErr: "not supported"},
		{name: "ipv6-join-group-on-ip4", spec: "IP4:127.0.0.1:1,ipv6-join-group=[ff02::2]:lo", wantErr: "not supported"},
		{name: "ipv6-join-group-on-udp6-recv", spec: "UDP6-RECV:1,ipv6-join-group=[ff02::2]:lo"},
		{name: "ipv6-join-group-on-tcp6", spec: "TCP6:localhost:1,ipv6-join-group=[ff02::2]:lo"},
		{name: "ip-add-membership-on-udp4", spec: "UDP4:localhost:1,ip-add-membership=224.0.0.1:lo"},
		{name: "ip-add-membership-on-udp6", spec: "UDP6:localhost:1,ip-add-membership=[ff02::2]:lo"},
		{name: "ip-add-membership-requires-value", spec: "UDP4:localhost:1,ip-add-membership", wantErr: "requires a value"},
		{name: "ipv6-join-group-requires-value", spec: "UDP6:localhost:1,ipv6-join-group", wantErr: "requires a value"},
		{name: "add-membership-alias-on-udp4", spec: "UDP4:localhost:1,add-membership=224.0.0.1:lo"},
		{name: "ip-membership-alias-on-udp4", spec: "UDP4:localhost:1,ip-membership=224.0.0.1:lo"},
		{name: "membership-alias-on-udp4", spec: "UDP4:localhost:1,membership=224.0.0.1:lo"},
		{name: "join-group-alias-on-udp6", spec: "UDP6:localhost:1,join-group=[ff02::2]:lo"},
		{name: "ipv6-add-membership-alias-on-udp6", spec: "UDP6:localhost:1,ipv6-add-membership=[ff02::2]:lo"},
		{name: "join-group-alias-on-udp4", spec: "UDP4:localhost:1,join-group=[ff02::2]:lo", wantErr: "not supported"},
		{name: "ipv6-add-membership-alias-on-tcp4", spec: "TCP4:localhost:1,ipv6-add-membership=[ff02::2]:lo", wantErr: "not supported"},
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
		{name: "pktinfo-on-udp4", spec: "UDP4:localhost:1,pktinfo"},
		{name: "tls-version-bounds", spec: "TLS:localhost:443,min-version=TLS1.2,max-version=TLS1.3"},
		{name: "classic-ip-aliases", spec: "TCP:localhost:1,ipttl=9,iptos=16"},
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
		{name: "handshake-timeout-on-tcp", spec: "TCP:host:port,handshake-timeout=1", wantErr: "not supported"},
		{name: "handshake-timeout-on-tcp-listen", spec: "TCP-LISTEN:1,handshake-timeout=1", wantErr: "not supported"},
		{name: "handshake-timeout-on-udp", spec: "UDP:localhost:1,handshake-timeout=1", wantErr: "not supported"},
		{name: "handshake-timeout-on-open", spec: "OPEN:file,handshake-timeout=1", wantErr: "not supported"},
		{name: "handshake-timeout-on-exec", spec: "EXEC:true,handshake-timeout=1", wantErr: "not supported"},
		{name: "handshake-timeout-on-tls", spec: "TLS:localhost:1,handshake-timeout=1"},
		{name: "handshake-timeout-on-tls-listen", spec: "TLS-LISTEN:1,handshake-timeout=0.2"},
		{name: "handshake-timeout-on-openssl", spec: "OPENSSL:localhost:1,handshake-timeout=1"},
		{name: "handshake-timeout-on-quic", spec: "QUIC:localhost:1,handshake-timeout=1"},
		{name: "handshake-timeout-on-quic-listen", spec: "QUIC-LISTEN:1,handshake-timeout=0.2"},
		{name: "handshake-timeout-on-ws", spec: "WS:localhost:1,handshake-timeout=1"},
		{name: "handshake-timeout-on-wss", spec: "WSS:localhost:1,handshake-timeout=1"},
		{name: "handshake-timeout-on-proxy", spec: "PROXY:localhost:example.com:443,handshake-timeout=1"},
		{name: "handshake-timeout-on-socks4", spec: "SOCKS4:localhost:example.com:80,handshake-timeout=1"},
		{name: "handshake-timeout-on-socks5", spec: "SOCKS5:localhost:example.com:443,handshake-timeout=1"},
		{name: "handshake-timeout-zero-on-tls", spec: "TLS:localhost:1,handshake-timeout=0"},
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
		{name: "bad-setsockopt-int-hex-value", spec: "TCP:localhost:1,setsockopt-int=1:9:x01", wantErr: "integer"},
		{name: "bad-setsockopt-arity", spec: "TCP:localhost:1,setsockopt=1:9", wantErr: "level:optname:value"},
		{name: "missing-ciphers", spec: "TLS:localhost:443,ciphers", wantErr: "requires a value"},
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
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error=%v want substring %q", err, tc.wantErr)
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

type aliasCanonicalGroups struct {
	alias, canonical string
	aliasGroups      []string
	canonicalGroups  []string
}

// advertisedAliasesWithDifferentClassicGroups returns advertised Go aliases
// (helpOpt.aliases plus parse aliases that are in classiccatalog.Options)
// whose catalog Groups differ from the Go canonical target's Groups.
func advertisedAliasesWithDifferentClassicGroups() []aliasCanonicalGroups {
	pairs := map[string]string{}
	for _, group := range helpOptionGroups() {
		for _, option := range group.opts {
			for _, alias := range option.aliases {
				pairs[strings.ToLower(alias)] = strings.ToLower(option.name)
			}
		}
	}
	for spelling := range classiccatalog.Options {
		canon := parse.CanonicalOptionName(spelling)
		if canon != spelling {
			pairs[spelling] = canon
		}
	}
	var out []aliasCanonicalGroups
	for alias, canonical := range pairs {
		if alias == canonical {
			continue
		}
		se, sok := classiccatalog.Lookup(alias)
		ce, cok := classiccatalog.Lookup(canonical)
		if !sok || !cok {
			continue
		}
		if reflect.DeepEqual(se.Groups, ce.Groups) {
			continue
		}
		out = append(out, aliasCanonicalGroups{
			alias: alias, canonical: canonical,
			aliasGroups: se.Groups, canonicalGroups: ce.Groups,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].alias != out[j].alias {
			return out[i].alias < out[j].alias
		}
		return out[i].canonical < out[j].canonical
	})
	return out
}

var spellingGroupAddressSpecs = []string{
	"UDP4:localhost:1",
	"UDP4-RECV:1",
	"TCP4:localhost:1",
	"IP4:127.0.0.1:1",
	"UDP6:localhost:1",
	"UDP6-RECV:1",
	"TCP6:localhost:1",
	"IP6:[::1]:1",
}

func TestAdvertisedAliasClassicGroupMismatches(t *testing.T) {
	discovered := advertisedAliasesWithDifferentClassicGroups()
	if len(discovered) != 0 {
		t.Fatalf("unexpected Go alias/canonical group mismatches (do not fold distinct classic options): %v", discovered)
	}
	// ipv6-join-group is advertised as its own option, not a parse/help alias
	// of ip-add-membership. Classic groups still differ (IP6 vs IP4+IP6).
	join, ok := classiccatalog.Lookup("ipv6-join-group")
	if !ok {
		t.Fatal("ipv6-join-group")
	}
	member, ok := classiccatalog.Lookup("ip-add-membership")
	if !ok {
		t.Fatal("ip-add-membership")
	}
	mismatches := []aliasCanonicalGroups{{
		alias: "ipv6-join-group", canonical: "ip-add-membership",
		aliasGroups: join.Groups, canonicalGroups: member.Groups,
	}}
	t.Logf("covered alias/canonical group mismatches: ipv6-join-group %v vs ip-add-membership %v", join.Groups, member.Groups)

	dummyValue := func(spelling string) string {
		switch spelling {
		case "ipv6-join-group", "ip-add-membership":
			return "[ff02::2]:lo"
		default:
			return "1"
		}
	}

	for _, m := range mismatches {
		rejected := 0
		for _, base := range spellingGroupAddressSpecs {
			ch, err := parse.ParseChannel(base)
			if err != nil {
				t.Fatalf("%s: %v", base, err)
			}
			addrType := ch.Single.Type
			canonOK := xio.ClassicAllowsOption(addrType, m.canonical)
			aliasOK := xio.ClassicAllowsOption(addrType, m.alias)
			if !canonOK || aliasOK {
				continue
			}
			rejected++
			spec := base + "," + m.alias + "=" + dummyValue(m.alias)
			ch, err = parse.ParseChannel(spec)
			if err != nil {
				t.Fatalf("%s: %v", spec, err)
			}
			err = validateChannelOptions(ch)
			if err == nil || !strings.Contains(err.Error(), "not supported") {
				t.Errorf("%s: error=%v want not supported (alias groups=%v canonical groups=%v)",
					spec, err, m.aliasGroups, m.canonicalGroups)
			}
		}
		if rejected == 0 {
			t.Errorf("%s -> %s: no sample address is in canonical groups but not alias groups", m.alias, m.canonical)
		}
	}
}

func TestIPv6JoinGroupAcceptedOnIPv6(t *testing.T) {
	for _, spec := range []string{
		"UDP6:localhost:1,ipv6-join-group=[ff02::2]:lo",
		"UDP6-RECV:1,ipv6-join-group=[ff02::2]:lo",
		"TCP6:localhost:1,ipv6-join-group=[ff02::2]:lo",
		"UDP6:localhost:1,join-group=[ff02::2]:lo",
		"TCP6:localhost:1,ipv6-add-membership=[ff02::2]:lo",
	} {
		ch, err := parse.ParseChannel(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if err := validateChannelOptions(ch); err != nil {
			t.Errorf("%s: %v", spec, err)
		}
	}
}

func TestIPAddMembershipAcceptedOnUDP4AndUDP6(t *testing.T) {
	for _, spec := range []string{
		"UDP4:localhost:1,ip-add-membership=224.0.0.1:lo",
		"UDP4-RECV:1,ip-add-membership=224.0.0.1:lo",
		"UDP6:localhost:1,ip-add-membership=[ff02::2]:lo",
		"UDP6-RECV:1,ip-add-membership=[ff02::2]:lo",
		"UDP4:localhost:1,add-membership=224.0.0.1:lo",
		"UDP4:localhost:1,membership=224.0.0.1:lo",
		"UDP6:localhost:1,ip-membership=[ff02::2]:lo",
	} {
		ch, err := parse.ParseChannel(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if err := validateChannelOptions(ch); err != nil {
			t.Errorf("%s: %v", spec, err)
		}
	}
}

func TestValidateSpecOptionsUsesOriginalSpellingNotFoldedName(t *testing.T) {
	spec := parse.Spec{
		Type: "UDP4-RECV",
		Options: []parse.Option{{
			Name:     "ip-add-membership",
			Spelling: "ipv6-join-group",
			Value:    "[ff02::2]:lo",
			Has:      true,
		}},
	}
	err := validateSpecOptions(spec)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("folded Name must not bypass spelling groups: %v", err)
	}
}
