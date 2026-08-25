//go:build unix

package netopen

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUnixListenReuseaddrDoesNotUnlinkExistingFile(t *testing.T) {
	path := unixSocketTestPath(t, "leftover")
	if err := os.WriteFile(path, []byte("not-a-socket\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{"", ",reuseaddr"} {
		t.Run("opt"+extra, func(t *testing.T) {
			spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + extra)
			if err != nil {
				t.Fatal(err)
			}
			o, err := openUnixListen(context.Background(), spec, xio.ModeRDWR, nil)
			if err == nil {
				_ = o.Close()
				t.Fatal("UNIX-LISTEN replaced an existing file")
			}
			if !strings.Contains(err.Error(), "exists") {
				t.Fatalf("error=%v want exists", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "not-a-socket\n" {
				t.Fatalf("leftover file was replaced: %q", got)
			}
		})
	}
}

func TestUnixRecvReuseaddrDoesNotUnlinkExistingFile(t *testing.T) {
	path := unixSocketTestPath(t, "leftover")
	if err := os.WriteFile(path, []byte("not-a-socket\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("UNIX-RECV:" + path + ",reuseaddr")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecv(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("UNIX-RECV,reuseaddr replaced an existing file")
	}
	if !strings.Contains(err.Error(), "exists") {
		t.Fatalf("error=%v want exists", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "not-a-socket\n" {
		t.Fatalf("leftover file was replaced: %q", got)
	}
}

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

func TestUnixListenUnlinkEarlyReplacesExistingFile(t *testing.T) {
	path := unixSocketTestPath(t, "leftover")
	if err := os.WriteFile(path, []byte("not-a-socket\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",unlink-early,fork")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixListen(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("unlink-early left mode=%v", info.Mode())
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
