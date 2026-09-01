//go:build windows

package netopen

import (
	"context"
	"io"
	"net"
	"os"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func startWindowsUnixStreamPeer(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
}

func TestWindowsUnixConnectBindPreservesExistingFile(t *testing.T) {
	listen := testutil.UnixSocketPath(t, "listen.sock")
	bind := testutil.UnixSocketPath(t, "client.sock")
	startWindowsUnixStreamPeer(t, listen)
	if err := os.WriteFile(bind, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	spec := parse.Spec{
		Type:    "UNIX-CONNECT",
		Params:  []string{listen},
		Options: []parse.Option{{Name: "bind", Value: bind, Has: true}},
	}
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected bind of existing file to fail")
	}
	data, readErr := os.ReadFile(bind)
	if readErr != nil {
		t.Fatalf("existing bind path was removed: %v", readErr)
	}
	if string(data) != "keep" {
		t.Fatalf("bind path contents=%q", data)
	}
}

func TestWindowsUnixConnectBindPreservesLiveListenSocket(t *testing.T) {
	listen := testutil.UnixSocketPath(t, "listen.sock")
	bind := testutil.UnixSocketPath(t, "occupied.sock")
	startWindowsUnixStreamPeer(t, listen)
	startWindowsUnixStreamPeer(t, bind)

	spec := parse.Spec{
		Type:    "UNIX-CONNECT",
		Params:  []string{listen},
		Options: []parse.Option{{Name: "bind", Value: bind, Has: true}},
	}
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected bind of live listen socket to fail")
	}
	if _, statErr := os.Lstat(bind); statErr != nil {
		t.Fatalf("live listen socket was removed: %v", statErr)
	}
}

func TestWindowsUnixConnectFailedOpenUnlinksOnlyCreatedBind(t *testing.T) {
	missing := testutil.UnixSocketPath(t, "missing.sock")
	bind := testutil.UnixSocketPath(t, "client.sock")
	spec := parse.Spec{
		Type:    "UNIX-CONNECT",
		Params:  []string{missing},
		Options: []parse.Option{{Name: "bind", Value: bind, Has: true}},
	}
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected connect to missing dest to fail")
	}
	if _, statErr := os.Lstat(bind); !os.IsNotExist(statErr) {
		t.Fatalf("created bind path survived failed connect: %v", statErr)
	}
}

func TestWindowsUnixBindCreatedUnlinkPreservesReplacement(t *testing.T) {
	bind := testutil.UnixSocketPath(t, "client.sock")
	if err := os.WriteFile(bind, []byte("created"), 0o600); err != nil {
		t.Fatal(err)
	}
	created := rememberUnixBindCreated(bind)
	if err := os.Remove(bind); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bind, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	created.unlink()
	got, err := os.ReadFile(bind)
	if err != nil {
		t.Fatalf("replacement path was removed: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("replacement contents=%q", got)
	}
}
