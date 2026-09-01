//go:build linux

package netopen

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestSocketConnectStraceSocketArgs(t *testing.T) {
	if spec := os.Getenv("SOCAT_SOCKET_STRACE_CHILD"); spec != "" {
		s, err := parse.ParseSpec(spec)
		if err != nil {
			os.Exit(2)
		}
		_, _ = openSocketConnect(context.Background(), s, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
		os.Exit(0)
	}
	strace, err := exec.LookPath("strace")
	if err != nil {
		t.Skip("strace not installed")
	}
	cases := []struct {
		spec               string
		domain, typ, proto int
	}{
		{spec: "SOCKET-CONNECT:2:0:x00", domain: unix.AF_INET, typ: unix.SOCK_STREAM, proto: 0},
		{spec: "SOCKET-CONNECT:2:0:x00,socktype=2", domain: unix.AF_INET, typ: unix.SOCK_DGRAM, proto: 0},
		{spec: "SOCKET-CONNECT:2:0:x00,pf=10", domain: 10, typ: unix.SOCK_STREAM, proto: 0},
		{spec: "SOCKET-CONNECT:16:0:x00", domain: 16, typ: unix.SOCK_STREAM, proto: 0},
		{spec: "SOCKET-CONNECT:0x2:0x0:x00", domain: unix.AF_INET, typ: unix.SOCK_STREAM, proto: 0},
		{spec: "SOCKET-CONNECT::0:x00", domain: 0, typ: unix.SOCK_STREAM, proto: 0},
		{spec: "SOCKET-CONNECT:2:0:x00,so-protocol=6", domain: unix.AF_INET, typ: unix.SOCK_STREAM, proto: 6},
		{spec: "SOCKET-CONNECT:2:0:x00,so-prototype=6", domain: unix.AF_INET, typ: unix.SOCK_STREAM, proto: 6},
		{spec: "SOCKET-CONNECT:2:6:x00,protocol=17", domain: unix.AF_INET, typ: unix.SOCK_STREAM, proto: 17},
		{spec: "SOCKET-CONNECT:2:6:x00,so-protocol=7,protocol=6", domain: unix.AF_INET, typ: unix.SOCK_STREAM, proto: 6},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "strace.log")
			cmd := exec.Command(strace, "-f", "-e", "trace=socket", "-o", logPath, os.Args[0], "-test.run=^TestSocketConnectStraceSocketArgs$", "-test.count=1", "-test.v=false")
			cmd.Env = append(os.Environ(), "SOCAT_SOCKET_STRACE_CHILD="+tc.spec)
			out, err := cmd.CombinedOutput()
			body, _ := os.ReadFile(logPath)
			if !socketTraceHas(body, tc.domain, tc.typ, tc.proto) {
				t.Fatalf("socket(%d,%d,%d) not in strace (run err=%v)\nstrace:\n%s\nstderr:\n%s",
					tc.domain, tc.typ, tc.proto, err, body, out)
			}
		})
	}
}

var straceSocketRe = regexp.MustCompile(`socket\(([^,]+), ([^,]+), ([^)]+)\)`)

func socketTraceHas(log []byte, domain, typ, proto int) bool {
	for _, line := range strings.Split(string(log), "\n") {
		m := straceSocketRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		gotDom, ok1 := parseStraceSocketArg(m[1], straceFamilyValue)
		gotTyp, ok2 := parseStraceSocketArg(m[2], straceTypeValue)
		gotProto, ok3 := parseStraceSocketArg(m[3], straceProtoValue)
		if ok1 && ok2 && ok3 && gotDom == domain && gotTyp == typ && gotProto == proto {
			return true
		}
	}
	return false
}

func parseStraceSocketArg(arg string, named map[string]int) (int, bool) {
	arg = strings.TrimSpace(arg)
	var total int
	for _, part := range strings.Split(arg, "|") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if n, ok := named[part]; ok {
			total |= n
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return 0, false
		}
		total |= n
	}
	total &^= unix.SOCK_CLOEXEC
	total &^= unix.SOCK_NONBLOCK
	return total, true
}

var straceFamilyValue = map[string]int{
	"AF_UNSPEC":  unix.AF_UNSPEC,
	"AF_UNIX":    unix.AF_UNIX,
	"AF_LOCAL":   unix.AF_UNIX,
	"AF_INET":    unix.AF_INET,
	"AF_INET6":   unix.AF_INET6,
	"AF_NETLINK": unix.AF_NETLINK,
}

var straceTypeValue = map[string]int{
	"SOCK_STREAM":    unix.SOCK_STREAM,
	"SOCK_DGRAM":     unix.SOCK_DGRAM,
	"SOCK_RAW":       unix.SOCK_RAW,
	"SOCK_SEQPACKET": unix.SOCK_SEQPACKET,
	"SOCK_CLOEXEC":   unix.SOCK_CLOEXEC,
	"SOCK_NONBLOCK":  unix.SOCK_NONBLOCK,
}

var straceProtoValue = map[string]int{
	"IPPROTO_IP":    0,
	"IPPROTO_TCP":   unix.IPPROTO_TCP,
	"IPPROTO_UDP":   unix.IPPROTO_UDP,
	"NETLINK_ROUTE": 0,
}
