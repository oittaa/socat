package addrconfig

import (
	"strings"
	"testing"
	"time"
)

// omittedValueCase records one option's omitted-value rule.
// Signatures are from doc/socat.yo at classic tag-1.8.1.3 (12c08bf),
// except rows marked as Go extensions. "=<x>" requires "=".
// An explicit empty or whitespace value is kept.
// "[=<x>]" stores omission on Optional.Omitted. The string "1" is a real
// value, never a stand-in for omission.
type omittedValueCase struct {
	name      string
	signature string
	spec      string
	facts     Facts
	wantErr   string
	check     func(*testing.T, Address)
}

func TestOmittedNonBoolOptionValues(t *testing.T) {
	for _, tc := range omittedValueCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(mustParseSpec(t, tc.spec), tc.facts)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

var (
	shellFacts = Facts{Type: "SHELL", Kind: AddressKindSHELL}
	execFacts  = Facts{Type: "EXEC", Kind: AddressKindEXEC}
	fdFacts    = Facts{Type: "FD", Kind: AddressKindFD}
	ptyFacts   = Facts{Type: "PTY"}
	udp4Facts  = Facts{Type: "UDP4", Kind: AddressKindUDP, Role: AddressRoleConnect, Family: IPFamilyIPv4}
	tlsFacts   = Facts{Type: "OPENSSL", Role: AddressRoleConnect}
	wsFacts    = Facts{Type: "WS", Kind: AddressKindWebSocket, Role: AddressRoleConnect}
	proxyFacts = Facts{Type: "PROXY", Kind: AddressKindPROXY, Role: AddressRoleConnect}
	socksFacts = Facts{Type: "SOCKS", Kind: AddressKindSOCKS, Role: AddressRoleConnect}
	unixFacts  = Facts{Type: "UNIX-CONNECT", Kind: AddressKindUNIX, Role: AddressRoleConnect}
)

func wantText(get func(Address) OptionalString, value string) func(*testing.T, Address) {
	return func(t *testing.T, a Address) {
		t.Helper()
		got := get(a)
		if !got.Set || got.Omitted || got.Value != value {
			t.Fatalf("value=%+v want %q", got, value)
		}
	}
}

func wantOmitted(get func(Address) OptionalString) func(*testing.T, Address) {
	return func(t *testing.T, a Address) {
		t.Helper()
		got := get(a)
		if !got.Set || !got.Omitted || got.Value != "" {
			t.Fatalf("omitted=%+v", got)
		}
	}
}

var omittedValueCases = []omittedValueCase{
	{name: "shell", signature: "shell=<filename>", spec: "SHELL:true,shell", facts: shellFacts, wantErr: `option "shell": requires a value`},
	{name: "shell=", signature: "shell=<filename> (empty is a value)", spec: "SHELL:true,shell=", facts: shellFacts, check: wantText(func(a Address) OptionalString { return a.Process.Shell }, "")},
	{name: "shell=1", signature: "shell=<filename>", spec: "SHELL:true,shell=1", facts: shellFacts, check: wantText(func(a Address) OptionalString { return a.Process.Shell }, "1")},
	{name: "cert", signature: "cert=<filename>", spec: "OPENSSL:127.0.0.1:9,cert", facts: tlsFacts, wantErr: `option "cert": requires a value`},
	{name: "cert=", signature: "cert=<filename> (empty is a value)", spec: "OPENSSL:127.0.0.1:9,cert=", facts: tlsFacts, check: wantText(func(a Address) OptionalString { return a.TLS.Certificate }, "")},
	{name: "cert=1", signature: "cert=<filename>", spec: "OPENSSL:127.0.0.1:9,cert=1", facts: tlsFacts, check: wantText(func(a Address) OptionalString { return a.TLS.Certificate }, "1")},
	{name: "key", signature: "key=<filename>", spec: "OPENSSL:127.0.0.1:9,key", facts: tlsFacts, wantErr: `option "key": requires a value`},
	{name: "key=", signature: "key=<filename> (empty is a value)", spec: "OPENSSL:127.0.0.1:9,key=", facts: tlsFacts, check: wantText(func(a Address) OptionalString { return a.TLS.Key }, "")},
	{name: "cafile", signature: "cafile=<filename>", spec: "OPENSSL:127.0.0.1:9,cafile", facts: tlsFacts, wantErr: `option "cafile": requires a value`},
	{name: "cafile=", signature: "cafile=<filename> (empty is a value)", spec: "OPENSSL:127.0.0.1:9,cafile=", facts: tlsFacts, check: wantText(func(a Address) OptionalString { return a.TLS.CAFile }, "")},
	{name: "capath", signature: "capath=<dirname>", spec: "OPENSSL:127.0.0.1:9,capath", facts: tlsFacts, wantErr: `option "capath": requires a value`},
	{name: "capath=", signature: "capath=<dirname> (empty is a value)", spec: "OPENSSL:127.0.0.1:9,capath=", facts: tlsFacts, check: wantText(func(a Address) OptionalString { return a.TLS.CAPath }, "")},
	{name: "bind", signature: "bind=<sockname>", spec: "TCP:127.0.0.1:9,bind", facts: tcpConnect, wantErr: `option "bind": requires a value`},
	{name: "bind=", signature: "bind=<sockname> (empty is a value)", spec: "UNIX-CONNECT:/tmp/x,bind=", facts: unixFacts, check: func(t *testing.T, a Address) {
		if !a.Network.BindSet || a.Network.Bind.Original() != "" {
			t.Fatalf("bind=%+v set=%v", a.Network.Bind, a.Network.BindSet)
		}
	}},
	{name: "bind=space", signature: "bind=<sockname> (whitespace is a value)", spec: `UNIX-CONNECT:/tmp/x,bind=" "`, facts: unixFacts, check: func(t *testing.T, a Address) {
		if !a.Network.BindSet || a.Network.Bind.Original() != " " {
			t.Fatalf("bind=%+v set=%v", a.Network.Bind, a.Network.BindSet)
		}
	}},
	{name: "bind=1", signature: "bind=<sockname>", spec: "TCP:127.0.0.1:9,bind=1", facts: tcpConnect, check: func(t *testing.T, a Address) {
		if !a.Network.BindSet || a.Network.Bind.Original() != "1" {
			t.Fatalf("bind=%+v set=%v", a.Network.Bind, a.Network.BindSet)
		}
	}},
	{name: "sourceport", signature: "sourceport=<port>", spec: "TCP:127.0.0.1:9,sourceport", facts: tcpConnect, wantErr: `option "sourceport": requires a value`},
	{name: "sourceport=1", signature: "sourceport=<port>", spec: "TCP:127.0.0.1:9,sourceport=1", facts: tcpConnect, check: func(t *testing.T, a Address) {
		if !a.Network.SourcePortSet || !a.Network.SourcePort.Numeric || a.Network.SourcePort.Number != 1 {
			t.Fatalf("sourceport=%+v", a.Network.SourcePort)
		}
	}},
	{name: "pf", signature: "pf=<string>", spec: "TCP:127.0.0.1:9,pf", facts: tcpConnect, wantErr: `option "pf": requires a value`},
	{name: "pf=1", signature: "pf=<string>", spec: "TCP:127.0.0.1:9,pf=1", facts: tcpConnect, check: func(t *testing.T, a Address) {
		if !a.Network.ProtocolSet || a.Network.ProtocolFamily != 1 {
			t.Fatalf("pf=%d set=%v", a.Network.ProtocolFamily, a.Network.ProtocolSet)
		}
	}},
	{name: "fdin", signature: "fdin=<fdnum>", spec: "EXEC:true,fdin", facts: execFacts, wantErr: `option "fdin": requires a value`},
	{name: "fdout", signature: "fdout=<fdnum>", spec: "EXEC:true,fdout", facts: execFacts, wantErr: `option "fdout": requires a value`},
	{name: "fdout=", signature: "fdout=<fdnum>", spec: "EXEC:true,fdout=", facts: execFacts, wantErr: `option "fdout": requires a value`},
	{name: "fdin=1", signature: "fdin=<fdnum>", spec: "EXEC:true,fdin=1", facts: execFacts, check: func(t *testing.T, a Address) {
		if !a.Process.FDIn.Set || a.Process.FDIn.Value != 1 {
			t.Fatalf("fdin=%+v", a.Process.FDIn)
		}
	}},
	{name: "seek", signature: "seek=<offset> (missing value defaults to 1, not 0)", spec: "FD:3,seek", facts: fdFacts, check: func(t *testing.T, a Address) {
		if offset := fileOffset(a, FileActionSeekStart); offset != 1 {
			t.Fatalf("seek offset=%d", offset)
		}
	}},
	{name: "seek-cur", signature: "seek-cur=<offset> (missing value defaults to 1, not 0)", spec: "FD:3,seek-cur", facts: fdFacts, check: func(t *testing.T, a Address) {
		if offset := fileOffset(a, FileActionSeekCurrent); offset != 1 {
			t.Fatalf("seek-cur offset=%d", offset)
		}
	}},
	{name: "seek-end", signature: "seek-end=<offset> (missing value defaults to 1, not 0)", spec: "FD:3,seek-end", facts: fdFacts, check: func(t *testing.T, a Address) {
		if offset := fileOffset(a, FileActionSeekEnd); offset != 1 {
			t.Fatalf("seek-end offset=%d", offset)
		}
	}},
	{name: "seek=1", signature: "seek=<offset>", spec: "FD:3,seek=1", facts: fdFacts, check: func(t *testing.T, a Address) {
		if offset := fileOffset(a, FileActionSeekStart); offset != 1 {
			t.Fatalf("seek offset=%d", offset)
		}
	}},
	{name: "ip-multicast-ttl", signature: "ip-multicast-ttl=<byte>", spec: "UDP4:127.0.0.1:9,ip-multicast-ttl", facts: udp4Facts, wantErr: `option "ip-multicast-ttl": requires a value`},
	{name: "ip-multicast-ttl=1", signature: "ip-multicast-ttl=<byte>", spec: "UDP4:127.0.0.1:9,ip-multicast-ttl=1", facts: udp4Facts, check: func(t *testing.T, a Address) {
		if multicastValue(a, MulticastTTLIPv4) != 1 {
			t.Fatalf("ttl=%d", multicastValue(a, MulticastTTLIPv4))
		}
	}},
	{name: "commonname", signature: "commonname=<string>", spec: "OPENSSL:127.0.0.1:9,commonname", facts: tlsFacts, wantErr: `option "commonname": requires a value`},
	{name: "commonname=", signature: "commonname=<string>", spec: "OPENSSL:127.0.0.1:9,commonname=", facts: tlsFacts, check: wantText(func(a Address) OptionalString { return a.TLS.CommonName }, "")},
	{name: "commonname=1", signature: "commonname=<string>", spec: "OPENSSL:127.0.0.1:9,commonname=1", facts: tlsFacts, check: wantText(func(a Address) OptionalString { return a.TLS.CommonName }, "1")},
	{name: "proxy-authorization", signature: "proxy-authorization=<username>:<password>", spec: "PROXY:proxy.test:target.test:80,proxy-authorization", facts: proxyFacts, wantErr: `option "proxy-authorization": requires a value`},
	{name: "proxy-authorization=", signature: "proxy-authorization=<username>:<password> (empty is a value)", spec: "PROXY:proxy.test:target.test:80,proxy-authorization=", facts: proxyFacts, check: wantText(func(a Address) OptionalString { return a.Proxy.Authorization }, "")},
	{name: "proxy-authorization-file", signature: "proxy-authorization-file=<filename>", spec: "PROXY:proxy.test:target.test:80,proxy-authorization-file", facts: proxyFacts, wantErr: `option "proxy-authorization-file": requires a value`},
	{name: "proxy-authorization-file=", signature: "proxy-authorization-file=<filename> (empty is a value)", spec: "PROXY:proxy.test:target.test:80,proxy-authorization-file=", facts: proxyFacts, check: wantText(func(a Address) OptionalString { return a.Proxy.AuthorizationFile }, "")},
	{name: "pty-interval", signature: "pty-interval=<seconds>", spec: "PTY,pty-interval", facts: ptyFacts, wantErr: `option "pty-interval": requires a value`},
	{name: "pty-interval=abc", signature: "pty-interval=<seconds>", spec: "PTY,pty-interval=abc", facts: ptyFacts, wantErr: `option "pty-interval": invalid value: "abc"`},
	{name: "pty-interval=1", signature: "pty-interval=<seconds>", spec: "PTY,pty-interval=1", facts: ptyFacts, check: func(t *testing.T, a Address) {
		if !a.Terminal.WaitInterval.Set || a.Terminal.WaitInterval.Value != time.Second {
			t.Fatalf("interval=%+v", a.Terminal.WaitInterval)
		}
	}},
	{name: "proxyport", signature: "proxyport=<TCP service>", spec: "PROXY:proxy.test:target.test:80,proxyport", facts: proxyFacts, wantErr: `option "proxyport": requires a value`},
	{name: "socksport", signature: "socksport=<tcp service>", spec: "SOCKS:socks.test:target.test:80,socksport", facts: socksFacts, wantErr: `option "socksport": requires a value`},
	{name: "socksport=", signature: "socksport=<tcp service> (empty keeps the positional port)", spec: "SOCKS5:127.0.0.1:12345:localhost:443,socksport=", facts: socksFacts, check: func(t *testing.T, a Address) {
		if !a.Proxy.SOCKSPortSet || a.Proxy.SOCKSPort.Text() != "12345" {
			t.Fatalf("socksport=%+v", a.Proxy.SOCKSPort)
		}
	}},
	{name: "socksuser", signature: "socksuser=<user>", spec: "SOCKS:socks.test:target.test:80,socksuser", facts: socksFacts, wantErr: `option "socksuser": requires a value`},
	{name: "socksuser=", signature: "socksuser=<user> (empty is a value)", spec: "SOCKS:socks.test:target.test:80,socksuser=", facts: socksFacts, check: wantText(func(a Address) OptionalString { return a.Proxy.SOCKSUser }, "")},
	{name: "socksuser=space", signature: "socksuser=<user> (whitespace is a value)", spec: `SOCKS:socks.test:target.test:80,socksuser=" "`, facts: socksFacts, check: wantText(func(a Address) OptionalString { return a.Proxy.SOCKSUser }, " ")},
	{name: "socksuser=1", signature: "socksuser=<user>", spec: "SOCKS:socks.test:target.test:80,socksuser=1", facts: socksFacts, check: wantText(func(a Address) OptionalString { return a.Proxy.SOCKSUser }, "1")},
	{name: "sockspass", signature: "sockspass=<string>", spec: "SOCKS:socks.test:target.test:80,sockspass", facts: socksFacts, wantErr: `option "sockspass": requires a value`},
	{name: "sockspass=", signature: "sockspass=<string> (empty password is a value)", spec: "SOCKS:socks.test:target.test:80,socksuser=nobody,sockspass=", facts: socksFacts, check: wantText(func(a Address) OptionalString { return a.Proxy.SOCKSPassword }, "")},
	{name: "sockspass=space", signature: "sockspass=<string> (whitespace password is a value)", spec: `SOCKS:socks.test:target.test:80,socksuser=nobody,sockspass=" "`, facts: socksFacts, check: wantText(func(a Address) OptionalString { return a.Proxy.SOCKSPassword }, " ")},
	{name: "alpn", signature: "Go extension alpn= (value required)", spec: "OPENSSL:127.0.0.1:9,alpn", facts: tlsFacts, wantErr: `option "alpn": requires a value`},
	{name: "alpn=1", signature: "Go extension alpn= (value required)", spec: "OPENSSL:127.0.0.1:9,alpn=1", facts: tlsFacts, check: wantText(func(a Address) OptionalString { return a.TLS.ALPN }, "1")},
	{name: "path", signature: "path=<string>", spec: "WS:example.test:443,path", facts: wsFacts, wantErr: `option "path": requires a value`},
	{name: "path=", signature: "path=<string> (empty keeps the positional path)", spec: "WS:127.0.0.1:8080/service,path=", facts: wsFacts, check: wantText(func(a Address) OptionalString { return a.TLS.WSPath }, "/service")},
	{name: "path=1", signature: "path=<string>", spec: "WS:example.test:443,path=1", facts: wsFacts, check: wantText(func(a Address) OptionalString { return a.TLS.WSPath }, "/1")},
	{name: "origin", signature: "Go extension origin (value required)", spec: "WS:example.test:443,origin", facts: wsFacts, wantErr: `option "origin": requires a value`},
	{name: "origin=", signature: "Go extension origin (empty is a value)", spec: "WS:example.test:443,origin=", facts: wsFacts, check: wantText(func(a Address) OptionalString { return a.TLS.WSOrigin }, "")},
	{name: "protocol", signature: "Go extension WebSocket protocol (value required)", spec: "WS:example.test:443,protocol", facts: wsFacts, wantErr: `option "protocol": requires a value`},
	{name: "protocol=", signature: "Go extension WebSocket protocol (empty is a value)", spec: "WS:example.test:443,protocol=", facts: wsFacts, check: wantText(func(a Address) OptionalString { return a.TLS.WSProtocol }, "")},
	{name: "unix-bind-tempname", signature: "unix-bind-tempname[=/tmp/pre-XXXXXX]", spec: "UNIX-CONNECT:/tmp/x,unix-bind-tempname", facts: unixFacts, check: wantOmitted(func(a Address) OptionalString { return a.Network.UnixBindTempname })},
	{name: "unix-bind-tempname=", signature: "unix-bind-tempname[=/tmp/pre-XXXXXX] (empty follows classic)", spec: "UNIX-CONNECT:/tmp/x,unix-bind-tempname=", facts: unixFacts, check: wantText(func(a Address) OptionalString { return a.Network.UnixBindTempname }, "")},
	{name: "unix-bind-tempname=1", signature: "unix-bind-tempname[=/tmp/pre-XXXXXX]", spec: "UNIX-CONNECT:/tmp/x,unix-bind-tempname=1", facts: unixFacts, check: wantText(func(a Address) OptionalString { return a.Network.UnixBindTempname }, "1")},
	{name: "tcpwrap", signature: "tcpwrap[=<name>]", spec: "TCP:127.0.0.1:9,tcpwrap", facts: tcpConnect, check: func(t *testing.T, a Address) {
		if !a.Network.TCPWrap.Set || !a.Network.TCPWrap.Value || !a.Network.TCPWrapDaemon.Omitted {
			t.Fatalf("tcpwrap=%+v daemon=%+v", a.Network.TCPWrap, a.Network.TCPWrapDaemon)
		}
	}},
	{name: "tcpwrap=1", signature: "tcpwrap[=<name>]", spec: "TCP:127.0.0.1:9,tcpwrap=1", facts: tcpConnect, check: wantText(func(a Address) OptionalString { return a.Network.TCPWrapDaemon }, "1")},
	{name: "setpgid", signature: "setpgid=<pid_t> (omission documented)", spec: "EXEC:true,setpgid", facts: execFacts, check: func(t *testing.T, a Address) {
		if !a.Process.SetPGID.Set || a.Process.SetPGID.Value != 1 {
			t.Fatalf("setpgid=%+v", a.Process.SetPGID)
		}
	}},
	{name: "children-shutup", signature: "children-shutup[=1|2|..]", spec: "TCP:127.0.0.1:9,children-shutup", facts: tcpConnect, check: func(t *testing.T, a Address) {
		if !a.Common.ChildrenShutup.Set || a.Common.ChildrenShutup.Value != 1 {
			t.Fatalf("children-shutup=%+v", a.Common.ChildrenShutup)
		}
	}},
}

func fileOffset(a Address, kind FileActionKind) int64 {
	for _, action := range a.File.Actions {
		if action.Kind == kind {
			return action.Offset
		}
	}
	return -1
}
