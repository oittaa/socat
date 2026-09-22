//go:build linux

package xio_test

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestUDP6ForkKeepsKernelScopeWhenInterfaceNameIsNumeric(t *testing.T) {
	zone := addDigitScopeCollision(t)
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "UDP6-LISTEN:0,fork,reuseaddr,bind=[::],range=[fe80::]/10")
	cli := openClient(t, ctx, g, "UDP6:[fe80::1%"+zone+"]:"+tcpPort(t, srv))
	echoLive(t, streamOf(t, cli), []byte("ping"))
}

// addDigitScopeCollision creates two disconnected veth pairs and renames one
// end to the other pair's interface index. A reply transmitted on that
// digit-named interface cannot reach the client.
func addDigitScopeCollision(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN) to create a digit-named interface")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip not available")
	}
	zone := "scopea"
	for _, dev := range []string{zone, "sinka", "holder", "sinkb"} {
		_ = exec.Command("ip", "link", "del", dev).Run()
	}
	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s: %v %s", strings.Join(args, " "), err, out)
		}
	}
	run("link", "add", zone, "type", "veth", "peer", "name", "sinka")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", zone).Run() })
	run("link", "add", "holder", "type", "veth", "peer", "name", "sinkb")
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "holder").Run()
		_ = exec.Command("ip", "link", "del", "sinkb").Run()
	})
	for _, dev := range []string{zone, "sinka", "holder", "sinkb"} {
		run("link", "set", dev, "up")
	}
	ifi, err := net.InterfaceByName(zone)
	if err != nil {
		t.Fatal(err)
	}
	digit := strconv.Itoa(ifi.Index)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", digit).Run() })
	run("link", "set", "dev", "holder", "name", digit)
	named, err := net.InterfaceByName(digit)
	if err != nil {
		t.Fatal(err)
	}
	if named.Index == ifi.Index {
		t.Fatalf("interface %s has index %d; the name does not collide with a different scope id", digit, named.Index)
	}
	run("-6", "addr", "add", "fe80::1/64", "dev", zone, "nodad")
	run("-6", "addr", "add", "fe80::2/64", "dev", digit, "nodad")
	return zone
}
