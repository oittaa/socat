//go:build linux || darwin

package netopen

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUnixRecvfromReuseaddrDoesNotUnlinkExistingFile(t *testing.T) {
	path := unixSocketTestPath(t, "leftover")
	if err := os.WriteFile(path, []byte("not-a-socket\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",reuseaddr")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecvfrom(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("UNIX-RECVFROM,reuseaddr replaced an existing file")
	}
	if !strings.Contains(err.Error(), "exists") {
		t.Fatalf("error=%v want exists", err)
	}
}

func TestUnixListenUnlinkEarlyMissingPathSucceeds(t *testing.T) {
	path := unixSocketTestPath(t, "missing")
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",unlink-early,fork")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixListen(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
}
