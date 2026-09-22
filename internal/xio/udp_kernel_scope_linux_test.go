//go:build linux

package xio_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The forked session dials on another goroutine, so the process that runs
// the listener has to be inside the namespace that owns both interfaces.
func TestUDP6ForkKeepsKernelScopeWhenInterfaceNameIsNumeric(t *testing.T) {
	if os.Getenv("SOCAT_SCOPE_NS") == "1" {
		ctx, g := testCtx(t), testGlobal()
		srv := startForkListenPIPE(t, ctx, g, "UDP6-LISTEN:0,fork,reuseaddr,bind=[::],range=[fe80::]/10")
		cli := openClient(t, ctx, g, "UDP6:[fe80::1%scopea]:"+tcpPort(t, srv))
		echoLive(t, streamOf(t, cli), []byte("ping"))
		return
	}
	ns := digitScopeNetNS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "SOCAT_SCOPE_NS=1")
	out, err := cmd.CombinedOutput()
	if err != nil || bytes.Contains(out, []byte("no tests to run")) {
		t.Fatalf("kernel scope echo: %v\n%s", err, out)
	}
}

// digitScopeNetNS creates two disconnected veth pairs in a new namespace and
// renames one end to the other pair's interface index. A reply transmitted
// on that digit-named interface cannot reach the client. Cleanup removes
// only the namespace this function created.
func digitScopeNetNS(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN) to create a network namespace and a digit-named interface")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip not available")
	}
	ns := fmt.Sprintf("socat-scope-%d-%d", os.Getpid(), time.Now().UnixNano()%1e6)
	out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput()
	if err != nil {
		t.Fatalf("ip netns add %s: %v %s", ns, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	run := func(args ...string) {
		t.Helper()
		cmd := append([]string{"netns", "exec", ns}, args...)
		out, err := exec.Command("ip", cmd...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s: %v %s", strings.Join(cmd, " "), err, out)
		}
	}
	// Link-local delivery uses loopback.
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "scopea", "type", "veth", "peer", "name", "sinka")
	run("ip", "link", "add", "holder", "type", "veth", "peer", "name", "sinkb")
	for _, dev := range []string{"scopea", "sinka", "holder", "sinkb"} {
		run("ip", "link", "set", dev, "up")
	}
	scopeIndex := linkIndexInNS(t, ns, "scopea")
	digit := strconv.Itoa(scopeIndex)
	run("ip", "link", "set", "dev", "holder", "name", digit)
	if named := linkIndexInNS(t, ns, digit); named == scopeIndex {
		t.Fatalf("interface %s has index %d; the name does not collide with a different scope id", digit, named)
	}
	run("ip", "-6", "addr", "add", "fe80::1/64", "dev", "scopea", "nodad")
	run("ip", "-6", "addr", "add", "fe80::2/64", "dev", digit, "nodad")
	return ns
}

func linkIndexInNS(t *testing.T, ns, name string) int {
	t.Helper()
	out, err := exec.Command("ip", "netns", "exec", ns, "ip", "-o", "link", "show", "dev", name).CombinedOutput()
	if err != nil {
		t.Fatalf("ip link show %s: %v %s", name, err, out)
	}
	field, _, ok := strings.Cut(string(out), ":")
	if !ok {
		t.Fatalf("ip link show %s: %s", name, out)
	}
	n, err := strconv.Atoi(strings.TrimSpace(field))
	if err != nil || n <= 0 {
		t.Fatalf("index %q from %s", field, out)
	}
	return n
}
