//go:build linux

package netopen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
)

func TestUDP4ExclusiveRebindUsesNamespaceAddress(t *testing.T) {
	ns := namespaceWithAddress(t, "192.0.2.77/32")
	log := logx.New()
	log.SetLevel(logx.Error)
	spec := fmt.Sprintf("UDP4-LISTEN:0,bind=192.0.2.77,fork,reuseaddr=0,accept-timeout=0.2,netns=%s", ns)
	o, err := xio.OpenSpec(context.Background(), parseUDPSpec(t, spec), xio.ModeRDWR, xio.NewSession(xio.Options{Experimental: true, BlockSize: 8192}, log))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if err := writeUDPInNetNS(ns, o.Listener().Addr().(*net.UDPAddr), []byte("hi")); err != nil {
		t.Fatal(err)
	}
	conn, err := o.Listener().Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if _, err = o.Listener().Accept(); !errors.Is(err, xio.ErrAcceptTimeout) {
		t.Fatalf("accept after close: %v", err)
	}
}

func namespaceWithAddress(t *testing.T, cidr string) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN) to bind an address that exists only in a network namespace")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip not available")
	}
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip}); err == nil {
		_ = c.Close()
		t.Fatalf("%s is present on the host", ip)
	}
	ns := fmt.Sprintf("socat-rebind-%d", os.Getpid())
	if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add %s: %v %s", ns, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	for _, args := range [][]string{
		{"netns", "exec", ns, "ip", "-4", "addr", "add", "dev", "lo", cidr},
		{"netns", "exec", ns, "ip", "link", "set", "lo", "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v %s", strings.Join(args, " "), err, out)
		}
	}
	return ns
}

func writeUDPInNetNS(ns string, addr *net.UDPAddr, payload []byte) error {
	return xio.WithNetNS(ns, nil, func() error {
		c, err := net.DialUDP("udp4", nil, addr)
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		_, err = c.Write(payload)
		return err
	})
}
