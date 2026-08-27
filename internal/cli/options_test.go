package cli

import (
	"reflect"
	"runtime"
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
		{name: "pty-on-inet-alias", spec: "INET:localhost:1,pty", wantErr: "not supported"},
		{name: "nodelay-on-inet-alias", spec: "INET:localhost:1,nodelay"},
		{name: "backlog-on-inet-listen-alias", spec: "INET-LISTEN:1,backlog=10"},
		{name: "socksuser-on-socks-alias", spec: "SOCKS:localhost:example.com:80,socksuser=user"},
		{name: "pty-on-udp-dgram-alias", spec: "UDP-DGRAM:localhost:1,pty", wantErr: "not supported"},
		{name: "echo-on-stdio", spec: "STDIO,echo", windowsErr: "not supported on this platform"},
		{name: "vintr-on-stdio", spec: "STDIO,vintr=3", windowsErr: "not supported on this platform"},
		{name: "sane-on-stdio", spec: "STDIO,sane", windowsErr: "not supported on this platform"},
		{name: "intr-alias-on-stdio", spec: "STDIO,intr=3", windowsErr: "not supported on this platform"},
		{name: "icanon-on-stdio", spec: "STDIO,icanon=0", windowsErr: "not supported on this platform"},
		{name: "ispeed-on-stdio", spec: "STDIO,ispeed=9600", windowsErr: "not supported on this platform"},
		{name: "pipes-on-tcp", spec: "TCP:localhost:1,pipes", wantErr: "not supported"},
		{name: "fork-on-udp-connect", spec: "UDP:localhost:1,fork", wantErr: "not supported"},
		{name: "udplite-send-cscov", spec: "UDPLITE4:localhost:1,udplite-send-cscov=8"},
		{name: "udplite-recv-cscov", spec: "UDPLITE4-LISTEN:1,udplite-recv-cscov=8"},
		{name: "udplite-cscov-on-tcp", spec: "TCP:localhost:1,udplite-send-cscov=8", wantErr: "not supported"},
		{name: "udplite-cscov-on-udp", spec: "UDP4:localhost:1,udplite-send-cscov=8", wantErr: "not supported"},
		{name: "fork-on-tcp-connect", spec: "TCP:localhost:1,fork"},
		{name: "fork-on-accept-fd", spec: "ACCEPT-FD:3,fork"},
		{name: "range-on-accept-fd", spec: "ACCEPT-FD:3,range=127.0.0.1/32"},
		{name: "sourceport-on-accept-fd", spec: "ACCEPT-FD:3,sourceport=1"},
		{name: "lowport-on-accept-fd", spec: "ACCEPT-FD:3,lowport"},
		{name: "tcpwrap-on-accept-fd", spec: "ACCEPT-FD:3,tcpwrap"},
		{name: "fork-on-accept-alias", spec: "ACCEPT:3,fork"},
		{name: "backlog-on-accept-fd", spec: "ACCEPT-FD:3,backlog=10", wantErr: "not supported"},
		{name: "accept-timeout-on-accept-fd", spec: "ACCEPT-FD:3,accept-timeout=0.1", wantErr: "not supported"},
		{name: "unlink-early-on-accept-fd", spec: "ACCEPT-FD:3,unlink-early", wantErr: "not supported"},
		{name: "pty-on-accept-fd", spec: "ACCEPT-FD:3,pty", wantErr: "not supported"},
		{name: "accept-timeout-on-tcp-listen", spec: "TCP-LISTEN:1,accept-timeout=0.1"},
		{name: "excl-on-tcp", spec: "TCP:localhost:1,excl", wantErr: "not supported"},
		{name: "unlink-close-on-tcp", spec: "TCP:localhost:1,unlink-close", wantErr: "not supported"},
		{name: "open-unlink", spec: "OPEN:file,unlink"},
		{name: "open-delete-alias", spec: "OPEN:file,delete"},
		{name: "open-remove-alias", spec: "OPEN:file,remove"},
		{name: "open-o-rdonly", spec: "OPEN:file,o-rdonly"},
		{name: "open-ndelay", spec: "OPEN:file,ndelay"},
		{name: "open-lock-alias", spec: "OPEN:file,lock"},
		{name: "open-new-alias", spec: "OPEN:file,new"},
		{name: "bytes-alias", spec: "TCP:localhost:1,bytes=4"},
		{name: "crlf-alias", spec: "TCP:localhost:1,crlf"},
		{name: "cr", spec: "TCP:localhost:1,cr"},
		{name: "cr-assignment", spec: "TCP:localhost:1,cr=0", wantErr: "no value permitted"},
		{name: "crnl-false", spec: "TCP:localhost:1,crnl=false", wantErr: "no value permitted"},
		{name: "crlf-assignment", spec: "TCP:localhost:1,crlf=1", wantErr: "no value permitted"},
		{name: "shut-down", spec: "TCP:localhost:1,shut-down"},
		{name: "shut-down-zero", spec: "TCP:localhost:1,shut-down=0"},
		{name: "shut-down-one", spec: "TCP:localhost:1,shut-down=1"},
		{name: "shut-none-false", spec: "TCP:localhost:1,shut-none=false", wantErr: "invalid"},
		{name: "shut-none-garbage", spec: "TCP:localhost:1,shut-none=garbage", wantErr: "invalid"},
		{name: "shut-null-off", spec: "TCP:localhost:1,shut-null=off", wantErr: "invalid"},
		{name: "shut-close-no", spec: "TCP:localhost:1,shut-close=no", wantErr: "invalid"},
		{name: "shut-enum-down", spec: "TCP:localhost:1,shut=down"},
		{name: "shut-bad", spec: "TCP:localhost:1,shut=foo", wantErr: "invalid"},
		{name: "close-alias", spec: "TCP:localhost:1,close"},
		{name: "cd-alias", spec: "SYSTEM:true,cd=/tmp"},
		{name: "create-o-excl", spec: "CREATE:file,o-excl", wantErr: "not supported"},
		{name: "open-perm-early", spec: "OPEN:file,perm-early=0600"},
		{name: "open-user-early-alias", spec: "OPEN:file,uid-e=0"},
		{name: "open-group-early-alias", spec: "OPEN:file,gid-e=0"},
		{name: "bad-perm-early", spec: "OPEN:file,perm-early=xyz", wantErr: "invalid perm-early"},
		{name: "unlink-on-tcp", spec: "TCP:localhost:1,unlink", wantErr: "not supported"},
		{name: "setsid-on-tcp", spec: "TCP:localhost:1,setsid"},
		{name: "dash-on-exec", spec: "EXEC:true,dash"},
		{name: "login-on-shell", spec: "SHELL:true,login"},
		{name: "setpgid-on-exec", spec: "EXEC:true,setpgid=0"},
		{name: "pgid-on-system", spec: "SYSTEM:true,pgid=0"},
		{name: "dash-on-tcp", spec: "TCP:localhost:1,dash", wantErr: "not supported"},
		{name: "setpgid-on-tcp", spec: "TCP:localhost:1,setpgid=0", wantErr: "not supported"},
		{name: "dash-on-file", spec: "OPEN:file,login", wantErr: "not supported"},
		{name: "setpgid-on-file", spec: "OPEN:file,pgid=0", wantErr: "not supported"},
		{name: "setpgid-garbage", spec: "EXEC:true,setpgid=no", wantErr: "invalid"},
		{name: "readbytes-on-tcp", spec: "TCP:localhost:1,readbytes=4"},
		{name: "lockfile-on-tcp", spec: "TCP:localhost:1,lockfile=/tmp/x"},
		{name: "waitlock-on-stdio", spec: "STDIO,waitlock=/tmp/x"},
		{name: "lockfile-missing-value", spec: "TCP:localhost:1,lockfile", wantErr: "requires a value"},
		{name: "waitlock-missing-value", spec: "ECHO,waitlock", wantErr: "requires a value"},
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
		{name: "ip-multicast-ttl", spec: "UDP4:localhost:1,ip-multicast-ttl=9"},
		{name: "multicast-ttl-alias", spec: "UDP4:localhost:1,multicast-ttl=4"},
		{name: "ip-multicast-loop-flag", spec: "UDP4:localhost:1,ip-multicast-loop"},
		{name: "mcloop-alias", spec: "UDP4:localhost:1,mcloop=0"},
		{name: "ip-multicast-if", spec: "UDP4:localhost:1,ip-multicast-if=127.0.0.1"},
		{name: "ipv6-multicast-loop-on-udp6", spec: "UDP6:localhost:1,ipv6-multicast-loop=0"},
		{name: "mcloop6-on-tcp6", spec: "TCP6:localhost:1,mcloop6"},
		{name: "ipv6-multicast-loop-on-udp4", spec: "UDP4:localhost:1,ipv6-multicast-loop", wantErr: "not supported"},
		{name: "mcloop6-on-tcp4", spec: "TCP4:localhost:1,mcloop6=0", wantErr: "not supported"},
		{name: "ip-add-source-membership", spec: "UDP4:localhost:1,ip-add-source-membership=232.1.1.1:127.0.0.1:127.0.0.1"},
		{name: "source-membership-alias", spec: "UDP4-RECV:1,source-membership=232.1.1.1:127.0.0.1:127.0.0.1"},
		{name: "ipv6-join-source-group", spec: "UDP6:localhost:1,ipv6-join-source-group=[ff3e::1]:lo:[::1]"},
		{name: "join-source-group-on-udp4", spec: "UDP4:localhost:1,join-source-group=[ff3e::1]:lo:[::1]", wantErr: "not supported"},
		{name: "ipv6-join-source-group-on-tcp4", spec: "TCP4:localhost:1,ipv6-join-source-group=[ff3e::1]:lo:[::1]", wantErr: "not supported"},
		{name: "ip-freebind", spec: "TCP4-LISTEN:1,ip-freebind"},
		{name: "freebind-alias", spec: "UDP:localhost:1,freebind=1"},
		{name: "freebind-signed-type-int", spec: "UDP:localhost:1,ip-freebind=-1"},
		{name: "freebind-invalid-word", spec: "UDP:localhost:1,ip-freebind=true", wantErr: "invalid"},
		{name: "ip-transparent", spec: "TCP4-LISTEN:1,ip-transparent"},
		{name: "transparent-alias", spec: "TCP:localhost:1,transparent=0"},
		{name: "ip-transparent-bool-range", spec: "TCP:localhost:1,ip-transparent=2", wantErr: "invalid"},
		{name: "ip-transparent-bool-word", spec: "TCP:localhost:1,ip-transparent=true", wantErr: "invalid"},
		{name: "ip-mtu-discover", spec: "UDP4:localhost:1,ip-mtu-discover=2"},
		{name: "mtudiscover-alias", spec: "UDP4:localhost:1,mtudiscover=1"},
		{name: "ipmtudiscover-alias", spec: "TCP4:localhost:1,ipmtudiscover=0"},
		{name: "ipv6-mtu-discover", spec: "UDP6:localhost:1,ipv6-mtu-discover=2"},
		{name: "mtudiscover6-alias", spec: "TCP6:localhost:1,mtudiscover6=1"},
		{name: "mtu-discover-requires-value", spec: "UDP4:localhost:1,ip-mtu-discover", wantErr: "requires a value"},
		{name: "mtu-discover-range", spec: "UDP4:localhost:1,ip-mtu-discover=3", wantErr: "invalid"},
		{name: "mtu-discover6-range", spec: "UDP6:localhost:1,ipv6-mtu-discover=-1", wantErr: "invalid"},
		{name: "ip-recverr-rejected", spec: "UDP4:localhost:1,ip-recverr", wantErr: "not supported"},
		{name: "recverr-alias-rejected", spec: "UDP:localhost:1,recverr=1", wantErr: "not supported"},
		{name: "ipv6-recverr-rejected", spec: "UDP6:localhost:1,ipv6-recverr", wantErr: "not supported"},
		{name: "ip-recverr-on-tcp-rejected", spec: "TCP:localhost:1,ip-recverr", wantErr: "not supported"},
		{name: "ip-multicast-ttl-too-large", spec: "UDP4:localhost:1,ip-multicast-ttl=256", wantErr: "invalid"},
		{name: "ip-multicast-loop-bool-range", spec: "UDP4:localhost:1,ip-multicast-loop=2", wantErr: "invalid"},
		{name: "ip-multicast-loop-bool-word", spec: "UDP4:localhost:1,ip-multicast-loop=true", wantErr: "invalid"},
		{name: "ipv6-multicast-loop-bool-range", spec: "UDP6:localhost:1,ipv6-multicast-loop=2", wantErr: "invalid"},
		{name: "ipv6-multicast-loop-bool-word", spec: "UDP6:localhost:1,ipv6-multicast-loop=true", wantErr: "invalid"},
		{name: "ip-add-source-membership-requires-value", spec: "UDP4:localhost:1,ip-add-source-membership", wantErr: "requires a value"},
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
		{name: "o-rdwr-on-open", spec: "OPEN:file,o-rdwr"},
		{name: "o-direct-alias", spec: "FILE:file,direct"},
		{name: "o-direct-underscore", spec: "GOPEN:file,o_direct"},
		{name: "o-direct-on-create", spec: "CREATE:file,o-direct", wantErr: "not supported"},
		{name: "o-direct-on-pipe", spec: "PIPE:file,o-direct"},
		{name: "o-direct-on-fifo", spec: "FIFO:file,o-direct"},
		{name: "o-direct-on-tcp", spec: "TCP:localhost:1,o-direct", wantErr: "not supported"},
		{name: "o-direct-on-fd", spec: "FD:3,o-direct", wantErr: "not supported"},
		{name: "o-sync-on-open", spec: "OPEN:file,o-sync"},
		{name: "sync-alias-on-open", spec: "OPEN:file,sync"},
		{name: "o-sync-on-create", spec: "CREATE:file,o-sync", wantErr: "not supported"},
		{name: "o-sync-on-tcp", spec: "TCP:localhost:1,o-sync", wantErr: "not supported"},
		{name: "o-dsync-on-open", spec: "OPEN:file,o-dsync"},
		{name: "o-rsync-on-open", spec: "OPEN:file,o-rsync"},
		{name: "o-noctty-on-open", spec: "OPEN:file,noctty"},
		{name: "o-nofollow-on-open", spec: "OPEN:file,o-nofollow"},
		{name: "o-directory-on-open", spec: "OPEN:file,directory"},
		{name: "o-largefile-on-open", spec: "OPEN:file,largefile"},
		{name: "async-on-fd", spec: "FD:3,async"},
		{name: "o-async-on-tcp", spec: "TCP:localhost:1,o-async"},
		{name: "lseek-on-fd", spec: "FD:3,lseek=0"},
		{name: "seek-cur-on-open", spec: "OPEN:file,seek-cur=-1"},
		{name: "lseek-on-tcp", spec: "TCP:localhost:1,lseek=0", wantErr: "not supported"},
		{name: "flock-on-fd", spec: "FD:3,flock"},
		{name: "flock-ex-on-open", spec: "OPEN:file,flock-ex"},
		{name: "ioctl-void-on-open", spec: "OPEN:file,ioctl-void=0x541B"},
		{name: "ioctl-alias-on-tcp", spec: "TCP:localhost:1,ioctl=21531"},
		{name: "ioctl-intp-on-fd", spec: "FD:3,ioctl-intp=0x541B:0"},
		{name: "ioctl-int-on-tcp", spec: "TCP:localhost:1,ioctl-int=1:0"},
		{name: "ioctl-bin-on-open", spec: "OPEN:file,ioctl-bin=1:x01000000"},
		{name: "ioctl-string-on-fd", spec: "FD:3,ioctl-string=1:hello"},
		{name: "ioctl-string-quoted-trailing-space", spec: `FD:3,ioctl-string="1:hello "`},
		{name: "ioctl-string-empty", spec: "STDIN,ioctl-string=1:"},
		{name: "ioctl-void-fionread", spec: "FD:3,ioctl-void=0x541B"},
		{name: "ioctl-void-overflow", spec: "FD:3,ioctl-void=4294967296", wantErr: "invalid ioctl-void"},
		{name: "ioctl-void-hex-overflow", spec: "OPEN:file,ioctl-void=0x100000000", wantErr: "invalid ioctl-void"},
		{name: "ioctl-int-payload-overflow", spec: "FD:3,ioctl-int=1:4294967296", wantErr: "invalid ioctl-int"},
		{name: "ioctl-int-missing-colon", spec: "FD:3,ioctl-int=1", wantErr: "invalid ioctl-int"},
		{name: "ioctl-intp-garbage", spec: "TCP:localhost:1,ioctl-intp=1:nope", wantErr: "invalid ioctl-intp"},
		{name: "ioctl-bin-garbage", spec: "OPEN:file,ioctl-bin=1:not-a-dalan", wantErr: "invalid ioctl-bin"},
		{name: "ioctl-bin-empty", spec: "FD:3,ioctl-bin=1:", wantErr: "invalid ioctl-bin"},
		{name: "ioctl-bin-leftover", spec: "FD:3,ioctl-bin=1:512junk", wantErr: "invalid ioctl-bin"},
		{name: "ioctl-void-missing", spec: "FD:3,ioctl-void", wantErr: "requires a value"},
		{name: "ioctl-string-missing-colon", spec: "TCP:localhost:1,ioctl-string=1", wantErr: "invalid ioctl-string"},
		{name: "perm-late-on-fd", spec: "FD:3,perm-late=0600"},
		{name: "perm-late-on-open", spec: "OPEN:file,perm-late=0600"},
		{name: "user-late-on-fd", spec: "FD:3,uid-l=0"},
		{name: "group-late-on-fd", spec: "FD:3,gid-l=0"},
		{name: "missing-perm-late", spec: "FD:3,perm-late", wantErr: "requires a value"},
		{name: "bare-lseek-defaults-to-one", spec: "FD:3,lseek"},
		{name: "fs-noatime-on-open", spec: "OPEN:file,fs-noatime"},
		{name: "fs-noatime-on-create", spec: "CREATE:file,fs-noatime"},
		{name: "ext2-noatime-alias", spec: "OPEN:file,ext2-noatime"},
		{name: "ext3-noatime-alias", spec: "FD:3,ext3-noatime"},
		{name: "fs-noatime-on-tcp", spec: "TCP:localhost:1,fs-noatime", wantErr: "not supported"},
		{name: "fs-noatime-on-pipe", spec: "PIPE:file,fs-noatime", wantErr: "not supported"},
		{name: "fs-append-on-open", spec: "OPEN:file,fs-append"},
		{name: "fs-append-zero", spec: "OPEN:file,fs-append=0"},
		{name: "fs-append-one", spec: "OPEN:file,fs-append=1"},
		{name: "fs-nodump-garbage", spec: "OPEN:file,fs-nodump=garbage", wantErr: "invalid"},
		{name: "fs-nodump-bool-range", spec: "OPEN:file,fs-nodump=2", wantErr: "invalid"},
		{name: "fs-nodump-bool-word", spec: "OPEN:file,fs-nodump=true", wantErr: "invalid"},
		{name: "nodump-garbage-alias", spec: "OPEN:file,nodump=garbage", wantErr: "invalid"},
		{name: "ext2-append-alias", spec: "FD:3,ext2-append"},
		{name: "nodump-on-create", spec: "CREATE:file,nodump"},
		{name: "notail-on-open", spec: "OPEN:file,notail"},
		{name: "fs-append-on-tcp", spec: "TCP:localhost:1,fs-append", wantErr: "not supported"},
		{name: "fs-append-on-pipe", spec: "PIPE:file,fs-append", wantErr: "not supported"},
		{name: "fs-append-on-exec", spec: "EXEC:true,fs-append", wantErr: "not supported"},
		{name: "nodump-on-tcp", spec: "TCP:localhost:1,nodump", wantErr: "not supported"},
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
		{name: "tls-min-proto-version", spec: "TLS:localhost:443,min-proto-version=TLS1.2,max-proto-version=TLS1.3"},
		{name: "openssl-certificate", spec: "TLS:localhost:443,openssl-certificate=cert.pem"},
		{name: "certificate-alias", spec: "OPENSSL:localhost:443,certificate=cert.pem"},
		{name: "openssl-key", spec: "TLS:localhost:443,openssl-key=key.pem"},
		{name: "openssl-cafile", spec: "TLS:localhost:443,openssl-cafile=ca.pem"},
		{name: "openssl-verify", spec: "TLS:localhost:443,openssl-verify=0"},
		{name: "cn-alias", spec: "TLS:localhost:443,cn=localhost"},
		{name: "cipherlist", spec: "TLS:localhost:443,cipherlist=ECDHE-ECDSA-AES256-GCM-SHA384"},
		{name: "no-sni", spec: "TLS:localhost:443,no-sni"},
		{name: "openssl-method-on-tls", spec: "TLS:localhost:443,openssl-method=DTLS1"},
		{name: "method-on-tls", spec: "TLS:localhost:443,method=DTLS1"},
		{name: "fips-on-tls", spec: "TLS:localhost:443,fips"},
		{name: "openssl-fips-on-tls", spec: "OPENSSL:localhost:443,openssl-fips=1"},
		{name: "invalid-fips-value", spec: "TLS:localhost:443,fips=2", wantErr: "invalid"},
		{name: "compress-on-tls", spec: "TLS:localhost:443,compress=none"},
		{name: "compress-requires-value", spec: "TLS:localhost:443,compress", wantErr: "requires a value"},
		{name: "egd-on-tls", spec: "TLS:localhost:443,egd=/dev/urandom"},
		{name: "method-requires-value", spec: "TLS:localhost:443,method", wantErr: "requires a value"},
		{name: "pseudo-on-tls", spec: "TLS:localhost:443,pseudo"},
		{name: "dhparam-on-tls", spec: "TLS:localhost:443,dhparam=dh.pem"},
		{name: "maxfraglen-on-tls", spec: "TLS:localhost:443,maxfraglen=512"},
		{name: "invalid-maxfraglen", spec: "TLS:localhost:443,maxfraglen=bad", wantErr: "invalid"},
		{name: "maxsendfrag-on-tls", spec: "TLS:localhost:443,maxsendfrag=1024"},
		{name: "compress-on-tcp", spec: "TCP:localhost:1,compress=none", wantErr: "not supported"},
		{name: "method-on-tcp", spec: "TCP:localhost:1,method=DTLS1", wantErr: "not supported"},
		{name: "dhparam-on-tcp", spec: "TCP:localhost:1,dh=dh.pem", wantErr: "not supported"},
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
		{name: "ignorecr-on-proxy", spec: "PROXY:localhost:example.com:80,ignorecr"},
		{name: "ignorecr-zero-on-proxy", spec: "PROXY:localhost:example.com:80,ignorecr=0"},
		{name: "ignorecr-one-on-proxy", spec: "PROXY:localhost:example.com:80,ignorecr=1"},
		{name: "ignorecr-bool-range", spec: "PROXY:localhost:example.com:80,ignorecr=2", wantErr: "invalid"},
		{name: "ignorecr-on-socks", spec: "SOCKS4:localhost:example.com:80,ignorecr", wantErr: "not supported"},
		{name: "ignorecr-on-tcp", spec: "TCP:localhost:1,ignorecr", wantErr: "not supported"},
		{name: "socks-option-on-proxy", spec: "PROXY:localhost:example.com:80,socksuser=user", wantErr: "not supported"},
		{name: "backlog-on-tcp", spec: "TCP-LISTEN:1,backlog=10"},
		{name: "hex-max-children", spec: "TCP-LISTEN:1,fork,max-children=0x10"},
		{name: "octal-max-children", spec: "TCP-LISTEN:1,fork,max-children=010"},
		{name: "octal-ftruncate", spec: "OPEN:file,ftruncate=010"},
		{name: "backlog-on-socket", spec: "SOCKET-LISTEN:2:0:x00,backlog=10"},
		{name: "nodelay-on-file", spec: "CREATE:file,nodelay", wantErr: "not supported"},
		{name: "keepalive-on-udp", spec: "UDP:localhost:1,keepalive"},
		{name: "nodelay-on-udp", spec: "UDP:localhost:1,nodelay", wantErr: "not supported"},
		{name: "tcp-cork-on-tcp", spec: "TCP:localhost:1,tcp-cork"},
		{name: "cork-alias-on-tls", spec: "TLS:localhost:1,cork=1"},
		{name: "tcp-maxseg-late-on-wss", spec: "WSS:localhost:1,maxseg-late=512"},
		{name: "so-dontroute-on-udp", spec: "UDP:localhost:1,dontroute"},
		{name: "so-oobinline-on-tcp", spec: "TCP:localhost:1,so-oobinline=1"},
		{name: "tcp-cork-on-udp", spec: "UDP:localhost:1,tcp-cork", wantErr: "not supported"},
		{name: "tcp-maxseg-on-udp", spec: "UDP:localhost:1,maxseg=512", wantErr: "not supported"},
		{name: "tcp-cork-on-sctp", spec: "SCTP:localhost:1,tcp-cork", wantErr: "not supported"},
		{name: "tcp-maxseg-late-on-sctp", spec: "SCTP4:localhost:1,tcp-maxseg-late=512", wantErr: "not supported"},
		{name: "sctp-nodelay-on-sctp", spec: "SCTP:localhost:1,sctp-nodelay"},
		{name: "sctp-maxseg-on-sctp4", spec: "SCTP4:localhost:1,sctp-maxseg=1400"},
		{name: "sctp-nodelay-on-sctp-listen", spec: "SCTP-LISTEN:1,sctp-nodelay"},
		{name: "sctp-maxseg-on-sctp4-listen", spec: "SCTP4-LISTEN:1,sctp-maxseg=1400"},
		{name: "sctp-nodelay-on-tcp", spec: "TCP:localhost:1,sctp-nodelay", wantErr: "not supported"},
		{name: "sctp-maxseg-on-udp", spec: "UDP:localhost:1,sctp-maxseg=1400", wantErr: "not supported"},
		{name: "sctp-nodelay-on-quic", spec: "QUIC:localhost:1,sctp-nodelay", wantErr: "not supported"},
		{name: "sctp-maxseg-on-file", spec: "OPEN:file,sctp-maxseg=1400", wantErr: "not supported"},
		{name: "tcp-cork-on-file", spec: "OPEN:file,tcp-cork", wantErr: "not supported"},
		{name: "append-on-tcp", spec: "TCP:localhost:1,append"},
		{name: "append-on-fd", spec: "FD:3,append"},
		{name: "append-on-stdio", spec: "STDIO,append"},
		{name: "append-on-exec", spec: "EXEC:true,append"},
		{name: "cloexec-on-tcp", spec: "TCP:localhost:1,cloexec"},
		{name: "cloexec-on-fd", spec: "FD:3,cloexec=0"},
		{name: "cloexec-on-stdio", spec: "STDIO,cloexec=1"},
		{name: "cloexec-on-exec", spec: "EXEC:true,cloexec"},
		{name: "cloexec-on-open", spec: "OPEN:file,cloexec=0"},
		{name: "cloexec-garbage", spec: "FD:3,cloexec=no", wantErr: "invalid"},
		{name: "o-append-on-stdin", spec: "STDIN,o-append"},
		{name: "ftruncate-on-fd", spec: "FD:3,ftruncate=0"},
		{name: "truncate-alias-on-open", spec: "OPEN:file,truncate=0"},
		{name: "ftruncate32-on-fd", spec: "FD:3,ftruncate32=0"},
		{name: "ftruncate64-on-fd", spec: "FD:3,ftruncate64=0"},
		{name: "mode-on-fd", spec: "FD:3,mode=0600"},
		{name: "uid-on-fd", spec: "FD:3,uid=0"},
		{name: "owner-on-fd", spec: "FD:3,owner=0"},
		{name: "gid-on-fd", spec: "FD:3,gid=0"},
		{name: "ftruncate-on-tcp", spec: "TCP:localhost:1,ftruncate=0", wantErr: "not supported"},
		{name: "ftruncate32-on-tcp", spec: "TCP:localhost:1,ftruncate32=0", wantErr: "not supported"},
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
		{name: "missing-ip-options", spec: "UDP:localhost:1,ip-options", wantErr: "requires a value"},
		{name: "missing-linger", spec: "TCP:localhost:1,so-linger", wantErr: "requires a value"},
		{name: "missing-sndbuf", spec: "TCP:localhost:1,sndbuf", wantErr: "requires a value"},
		{name: "missing-user", spec: "FD:3,user", wantErr: "requires a value"},
		{name: "missing-owner", spec: "FD:3,owner", wantErr: "requires a value"},
		{name: "missing-group", spec: "FD:3,group", wantErr: "requires a value"},
		{name: "missing-user-early", spec: "OPEN:file,user-early", wantErr: "requires a value"},
		{name: "missing-group-early", spec: "OPEN:file,gid-e", wantErr: "requires a value"},
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

func TestFSFlagOptionsRejectNonBoolValues(t *testing.T) {
	names := []string{
		"fs-append", "fs-compr", "fs-dirsync", "fs-immutable", "fs-journal-data",
		"fs-noatime", "fs-nodump", "fs-notail", "fs-secrm", "fs-sync", "fs-topdir", "fs-unrm",
		"nodump",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			ch, err := parse.ParseChannel("OPEN:file," + name + "=garbage")
			if err != nil {
				t.Fatal(err)
			}
			err = validateChannelOptions(ch)
			if err == nil || !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("error=%v want invalid", err)
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
		{spelling: "cloexec", phase: "LATE", groups: []string{"FD"}},
		{spelling: "ftruncate", phase: "LATE", groups: []string{"REG"}},
		{spelling: "truncate", phase: "LATE", groups: []string{"REG"}},
		{spelling: "ftruncate32", phase: "LATE", groups: []string{"REG"}},
		{spelling: "ftruncate64", phase: "LATE", groups: []string{"REG"}},
		{spelling: "perm", phase: "FD", groups: []string{"FD", "NAMED"}},
		{spelling: "mode", phase: "FD", groups: []string{"FD", "NAMED"}},
		{spelling: "user", phase: "FD", groups: []string{"FD", "NAMED"}},
		{spelling: "uid", phase: "FD", groups: []string{"FD", "NAMED"}},
		{spelling: "owner", phase: "FD", groups: []string{"FD", "NAMED"}},
		{spelling: "group", phase: "FD", groups: []string{"FD", "NAMED"}},
		{spelling: "gid", phase: "FD", groups: []string{"FD", "NAMED"}},
		{spelling: "perm-late", phase: "LATE", groups: []string{"FD"}},
		{spelling: "user-late", phase: "LATE", groups: []string{"FD"}},
		{spelling: "group-late", phase: "LATE", groups: []string{"FD"}},
		{spelling: "async", phase: "LATE", groups: []string{"FD", "OPEN"}},
		{spelling: "o-async", phase: "LATE", groups: []string{"FD", "OPEN"}},
		{spelling: "o-sync", phase: "OPEN", groups: []string{"OPEN"}},
		{spelling: "lseek", phase: "LATE", groups: []string{"BLK", "REG"}},
		{spelling: "flock", phase: "FD", groups: []string{"FD"}},
		{spelling: "flock-ex", phase: "FD", groups: []string{"FD"}},
		{spelling: "ioctl", phase: "FD", groups: []string{"FD"}},
		{spelling: "ioctl-void", phase: "FD", groups: []string{"FD"}},
		{spelling: "ioctl-int", phase: "FD", groups: []string{"FD"}},
		{spelling: "ioctl-intp", phase: "FD", groups: []string{"FD"}},
		{spelling: "ioctl-bin", phase: "FD", groups: []string{"FD"}},
		{spelling: "ioctl-string", phase: "FD", groups: []string{"FD"}},
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
		case "ipv6-join-source-group", "ip-add-source-membership":
			return "[ff3e::1]:lo:[::1]"
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

func TestMulticastRemainingOptionsAccepted(t *testing.T) {
	for _, spec := range []string{
		"UDP6:localhost:1,ipv6-multicast-loop=0",
		"UDP6:localhost:1,mcloop6",
		"UDP6:localhost:1,ipv6-join-source-group=[ff3e::1]:lo:[::1]",
		"UDP6:localhost:1,join-source-group=[ff3e::1]:lo:[::1]",
		"UDP4:localhost:1,ip-add-source-membership=232.1.1.1:127.0.0.1:127.0.0.1",
		"UDP4:localhost:1,ip-multicast-ttl=9,ip-multicast-loop=0,ip-multicast-if=127.0.0.1",
		"TCP4-LISTEN:1,ip-freebind,ip-transparent",
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

func TestTermiosOptionsRecognizedWhenUnsupported(t *testing.T) {
	if xio.FeatureTERMIOS {
		t.Skip("termios is implemented on this platform")
	}
	table := buildSupportedAddressOptions()
	for _, name := range []string{"vintr", "intr", "icanon", "ispeed", "ospeed", "b115200"} {
		if _, ok := table[name]; !ok {
			t.Errorf("option table missing %q on a platform without termios", name)
		}
	}
}

func TestTermiosOptionTypesAreValidated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows rejects the entire TERMIOS group")
	}
	tests := []struct {
		spec    string
		wantErr bool
	}{
		{spec: "PTY,echo"},
		{spec: "PTY,echo=0"},
		{spec: "PTY,echo=1"},
		{spec: "PTY,echo=false", wantErr: true},
		{spec: "PTY,echo=", wantErr: true},
		{spec: "PTY,raw"},
		{spec: "PTY,raw=0", wantErr: true},
		{spec: "PTY,b9600"},
		{spec: "PTY,b9600=0", wantErr: true},
		{spec: "PTY,vintr=3"},
		{spec: "PTY,vintr", wantErr: true},
		{spec: "PTY,ispeed=9600"},
		{spec: "PTY,ispeed=garbage", wantErr: true},
		{spec: "PTY,tiocswinsz=80:24"},
		{spec: "PTY,tiocswinsz", wantErr: true},
		{spec: "PTY,ctty=0"},
		{spec: "PTY,ctty=off", wantErr: true},
		{spec: "PTY,termios-setflags=0:1"},
		{spec: "PTY,termios-setflags=4:1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			s, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			err = validateSpecOptions(s)
			if tc.wantErr && err == nil {
				t.Fatal("validation succeeded")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validation failed: %v", err)
			}
		})
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
