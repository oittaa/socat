package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
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
		{name: "openssl-cipher-alias", spec: "OPENSSL:localhost:443,cipher=ECDHE-ECDSA-AES256-GCM-SHA384"},
		{name: "proxy-tls-option", spec: "PROXY:localhost:example.com:443,verify=0"},
		{name: "classic-keepalive-aliases", spec: "TCP:localhost:1,tcp-keepidle=7,tcp-keepintvl=9,tcp-keepcnt=3"},
		{name: "classic-listen-timeout-alias", spec: "TCP-LISTEN:1,listen-timeout=0.1"},
		{name: "classic-ignoreof-alias", spec: "OPEN:file,ignoreof"},
		{name: "classic-linger-alias", spec: "TCP:localhost:1,linger=0"},
		{name: "children-shutup-bare", spec: "TCP-LISTEN:1,fork,children-shutup"},
		{name: "linux-fd-options", spec: "STDIN,o-noatime,f-setpipe-sz=4096"},
		{name: "noatime-on-tcp", spec: "TCP:localhost:1,noatime"},
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
		{name: "missing-linger", spec: "TCP:localhost:1,so-linger", wantErr: "requires a value"},
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
