//go:build linux

package xio_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestUDP6ForkKeepsKernelScopeWhenInterfaceNameIsNumeric(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN) to create a network namespace and a digit-named interface")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip not available")
	}
	ns, g := setupNetNS(t)
	// The pairs are not connected to each other. A reply transmitted on the
	// digit-named interface cannot reach the client on scopea.
	runNS(t, ns, "ip", "link", "add", "scopea", "type", "veth", "peer", "name", "sinka")
	runNS(t, ns, "ip", "link", "add", "holder", "type", "veth", "peer", "name", "sinkb")
	for _, dev := range []string{"scopea", "sinka", "holder", "sinkb"} {
		runNS(t, ns, "ip", "link", "set", dev, "up")
	}
	scopeIndex := netnsLinkIndex(t, ns, "scopea")
	digit := strconv.Itoa(scopeIndex)
	runNS(t, ns, "ip", "link", "set", "dev", "holder", "name", digit)
	runNS(t, ns, "ip", "-6", "addr", "add", "fe80::1/64", "dev", "scopea", "nodad")
	runNS(t, ns, "ip", "-6", "addr", "add", "fe80::2/64", "dev", digit, "nodad")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := xio.WithNetNS(ns, g, func() error {
		byName, err := net.InterfaceByName(digit)
		if err != nil {
			return err
		}
		if byName.Index == scopeIndex {
			return fmt.Errorf("interface %s has index %d; the name does not collide with a different scope id", digit, byName.Index)
		}
		ch, err := parse.ParseChannel("UDP6-LISTEN:0,fork,reuseaddr,bind=[::]")
		if err != nil {
			return err
		}
		opened, err := xio.OpenChannel(ctx, ch, xio.ModeRDWR, g)
		if err != nil {
			return err
		}
		defer func() { _ = opened.Close() }()
		if opened.Listener() == nil || opened.WrapDial() == nil {
			return fmt.Errorf("UDP6-LISTEN,fork did not return a wrapable listener")
		}
		port := opened.Listener().Addr().(*net.UDPAddr).Port

		client, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("fe80::1"), Zone: "scopea"})
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		errc := make(chan error, 1)
		go func() {
			errc <- xio.WithNetNS(ns, g, func() error {
				c, err := opened.Listener().Accept()
				if err != nil {
					return err
				}
				defer func() { _ = c.Close() }()
				st, err := opened.WrapDial()(c)
				if err != nil {
					return err
				}
				defer func() { _ = st.Close() }()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(st, buf); err != nil {
					return err
				}
				if string(buf) != "ping" {
					return fmt.Errorf("payload %q", buf)
				}
				_, err = st.Write([]byte("pong"))
				return err
			})
		}()

		dst := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: port, Zone: "scopea"}
		if _, err := client.WriteToUDP([]byte("ping"), dst); err != nil {
			return err
		}
		_ = client.SetReadDeadline(time.Now().Add(4 * time.Second))
		buf := make([]byte, 4)
		n, err := client.Read(buf)
		if err != nil {
			return fmt.Errorf("reply: %w", err)
		}
		if string(buf[:n]) != "pong" {
			return fmt.Errorf("reply %q", buf[:n])
		}
		return <-errc
	})
	if err != nil {
		t.Fatal(err)
	}
}

func runNS(t *testing.T, ns string, args ...string) {
	t.Helper()
	cmd := append([]string{"netns", "exec", ns}, args...)
	out, err := exec.Command("ip", cmd...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v %s", strings.Join(cmd, " "), err, out)
	}
}

func netnsLinkIndex(t *testing.T, ns, name string) int {
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
