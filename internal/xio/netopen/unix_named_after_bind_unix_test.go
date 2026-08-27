//go:build unix

package netopen

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUnixListenPermEarlyChmodsSocket(t *testing.T) {
	path := unixSocketTestPath(t, "listen.sock")
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",fork,perm-early=0600")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixListen(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	assertUnixSocketPerm(t, path, 0o600)
}

func TestUnixListenPermEarlyWinsOverPerm(t *testing.T) {
	path := unixSocketTestPath(t, "listen.sock")
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",fork,perm=0777,perm-early=0600")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixListen(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	assertUnixSocketPerm(t, path, 0o600)
}

func TestUnixRecvPermEarlyChmodsSocket(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	path := unixSocketTestPath(t, "recv.sock")
	spec, err := parse.ParseSpec("UNIX-RECV:" + path + ",perm-early=0600")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecv(context.Background(), spec, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	assertUnixSocketPerm(t, path, 0o600)
}

func TestUnixSendtoBindPermEarlyChmodsSocket(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	local := unixSocketTestPath(t, "local.sock")
	remote := unixSocketTestPath(t, "remote.sock")
	spec, err := parse.ParseSpec("UNIX-SENDTO:" + remote + ",bind=" + local + ",perm-early=0600")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixSendto(context.Background(), spec, xio.ModeWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	assertUnixSocketPerm(t, local, 0o600)
}

func TestUnixConnectBindPermEarlyChmodsSocket(t *testing.T) {
	listen := unixSocketTestPath(t, "listen.sock")
	bind := unixSocketTestPath(t, "client.sock")
	startUnixStreamPeer(t, listen)
	o := openBoundUnixConnect(t, listen, bind, parse.Option{Name: "perm-early", Value: "0600", Has: true})
	t.Cleanup(func() { _ = o.Close() })
	assertUnixSocketPerm(t, bind, 0o600)
}

func TestUnixConnectBindPermEarlyWinsOverPerm(t *testing.T) {
	// Classic UNIX-CONNECT applyopts_named after bind is PH_PREOPEN only
	// (perm-early on the bind path). perm= is PH_FD fchmod on the socket
	// descriptor via _xioopen_connect (tag-1.8.1.3
	// 12c08bf66d709fba17035ce95d85bd218428d9ba). Darwin fchmod on UNIX
	// sockets returns EINVAL; that error must propagate.
	listen := unixSocketTestPath(t, "listen.sock")
	bind := unixSocketTestPath(t, "client.sock")
	startUnixStreamPeer(t, listen)
	spec := parse.Spec{
		Type:   "UNIX-CONNECT",
		Params: []string{listen},
		Options: []parse.Option{
			{Name: "bind", Value: bind, Has: true},
			{Name: "perm", Value: "0777", Has: true},
			{Name: "perm-early", Value: "0600", Has: true},
		},
	}
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if runtime.GOOS != "linux" {
		if err == nil {
			t.Fatal("expected fchmod error on UNIX-CONNECT socket")
		}
		if !strings.Contains(err.Error(), "fchmod") {
			t.Fatalf("error=%v want fchmod EINVAL", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	assertUnixSocketPerm(t, bind, 0o600)
}

func TestUnixListenAbstractPermEarlyNoError(t *testing.T) {
	if !xio.FeatureABSTRACT {
		t.Skip("ABSTRACT UNIX not enabled")
	}
	spec, err := parse.ParseSpec("UNIX-LISTEN:@" + t.Name() + ",fork,perm-early=0600")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixListen(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
}

func TestAbstractListenPermAppliesToListenerDescriptorBeforeAccept(t *testing.T) {
	if !xio.FeatureABSTRACT {
		t.Skip("ABSTRACT UNIX not enabled")
	}
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) { ops = append(ops, op) })
	t.Cleanup(restore)
	spec, err := parse.ParseSpec("ABSTRACT-LISTEN:" + t.Name() + ",fork,perm=0600")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openAbstractListen(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	var fchmods int
	for _, op := range ops {
		if op == "fchmod" {
			fchmods++
		}
	}
	if fchmods != 1 {
		t.Fatalf("listener fchmod count=%d want 1 before accept (ops=%v)", fchmods, ops)
	}
}

func assertUnixSocketPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s mode=%v want socket", path, fi.Mode())
	}
	if got := fi.Mode().Perm(); got != want {
		t.Fatalf("%s perm=%#o want %#o", path, got, want)
	}
}
