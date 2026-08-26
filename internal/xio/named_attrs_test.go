//go:build unix

package xio

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestApplyNamedAttrsSetsPerm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named")
	if err := os.WriteFile(path, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",perm=0600")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedAttrs(path, spec, nil); err != nil {
		t.Fatal(err)
	}
	assertPathPerm(t, path, 0o600)
}

func TestApplyNamedAfterBindPermEarlyWinsOverPerm(t *testing.T) {
	// ApplyNamedAfterBind is chmod/chown of a path, not bind(2). Do not
	// net.Listen("unix") under t.TempDir(): Darwin sun_path is 104 bytes and
	// the macOS TempDir includes the test name (CI: bind: invalid argument).
	path := filepath.Join(t.TempDir(), "named")
	if err := os.WriteFile(path, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",perm=0777,perm-early=0600")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedAfterBind(path, spec, nil); err != nil {
		t.Fatal(err)
	}
	assertPathPerm(t, path, 0o600)
}

func TestApplyNamedAfterBindUserEarlyGroupEarlyCurrentIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	raw := "UNIX-LISTEN:" + path + ",user-early=" + strconv.Itoa(uid) + ",group-early=" + strconv.Itoa(gid)
	spec, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedAfterBind(path, spec, nil); err != nil {
		t.Fatal(err)
	}
	gotUID, gotGID := pathOwner(t, path)
	if gotUID != uid || gotGID != gid {
		t.Fatalf("owner=%d:%d want %d:%d", gotUID, gotGID, uid, gid)
	}
}

func TestApplyNamedAfterBindSkipsAbstract(t *testing.T) {
	spec, err := parse.ParseSpec("UNIX-LISTEN:@abs,perm-early=0600,user-early=0,group-early=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedAfterBind("@abs", spec, nil); err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedAfterBind("\x00abs", spec, nil); err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedAfterBind("", spec, nil); err != nil {
		t.Fatal(err)
	}
}

func TestApplyNamedPreopenPermEarly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",perm-early=0600")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedPreopen(path, spec); err != nil {
		t.Fatal(err)
	}
	assertPathPerm(t, path, 0o600)
}

func TestApplyNamedPreopenUserEarlyGroupEarlyCurrentIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	raw := "OPEN:" + path + ",user-early=" + strconv.Itoa(uid) + ",group-early=" + strconv.Itoa(gid)
	spec, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedPreopen(path, spec); err != nil {
		t.Fatal(err)
	}
	gotUID, gotGID := pathOwner(t, path)
	if gotUID != uid || gotGID != gid {
		t.Fatalf("owner=%d:%d want %d:%d", gotUID, gotGID, uid, gid)
	}
}

func TestApplyNamedPreopenUserEarlyUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",user-early=socat-user-that-must-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyNamedPreopen(path, spec)
	if err == nil || !strings.Contains(err.Error(), "user") {
		t.Fatalf("error=%v want user lookup failure", err)
	}
}

func TestApplyNamedPreopenUIDEAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	spec, err := parse.ParseSpec("OPEN:" + path + ",uid-e=" + strconv.Itoa(uid) + ",gid-e=" + strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedPreopen(path, spec); err != nil {
		t.Fatal(err)
	}
	gotUID, _ := pathOwner(t, path)
	if gotUID != uid {
		t.Fatalf("uid=%d want %d", gotUID, uid)
	}
}

func assertPathPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Fatalf("perm=%#o want %#o", got, want)
	}
}

func pathOwner(t *testing.T, path string) (uid, gid int) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat sys type %T", info.Sys())
	}
	return int(st.Uid), int(st.Gid)
}
