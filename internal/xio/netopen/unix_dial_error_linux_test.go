//go:build linux

package netopen

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUnixConnectMissingPathIsENOENT(t *testing.T) {
	path := unixSocketTestPath(t, "missing.sock")
	spec, err := parse.ParseSpec("UNIX-CONNECT:" + path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = openUnixConnect(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "connect") || !strings.Contains(err.Error(), path) {
		t.Fatalf("error=%v", err)
	}
	if !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("error=%v want ENOENT", err)
	}
}

func TestUnixConnectDatagramMissingPathIsENOENT(t *testing.T) {
	path := unixSocketTestPath(t, "missing.sock")
	spec, err := parse.ParseSpec("UNIX-CONNECT:" + path + ",socktype=" + strconv.Itoa(syscall.SOCK_DGRAM))
	if err != nil {
		t.Fatal(err)
	}
	_, err = openUnixConnect(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "connect") || !strings.Contains(err.Error(), path) {
		t.Fatalf("error=%v", err)
	}
	if !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("error=%v want ENOENT", err)
	}
}

func TestAbstractConnectMissingNameIdentifiesConnect(t *testing.T) {
	name := "missing-" + strings.ReplaceAll(t.Name(), "/", "-")
	spec, err := parse.ParseSpec("ABSTRACT-CONNECT:" + name)
	if err != nil {
		t.Fatal(err)
	}
	_, err = openAbstractConnect(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "connect") || !strings.Contains(err.Error(), name) {
		t.Fatalf("error=%v", err)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("error=%v want ECONNREFUSED", err)
	}
}

func TestUnixConnectRetryKeepsConnectError(t *testing.T) {
	path := unixSocketTestPath(t, "missing.sock")
	spec, err := parse.ParseSpec("UNIX-CONNECT:" + path + ",retry=1,interval=0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = openUnixConnect(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "connect") || !strings.Contains(err.Error(), path) {
		t.Fatalf("error=%v", err)
	}
	if !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("error=%v want ENOENT", err)
	}
}
