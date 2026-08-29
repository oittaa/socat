//go:build linux || darwin

package xio

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestWithUmaskSerializesUnspecifiedCreation(t *testing.T) {
	old := unix.Umask(0o022)
	defer unix.Umask(old)

	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- WithUmask(parse.Spec{
			Type:    "CREATE",
			Options: []parse.Option{{Name: "umask", Value: "077", Has: true}},
		}, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	path := filepath.Join(t.TempDir(), "normal-mode")
	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- WithUmask(parse.Spec{}, func() error {
			close(secondEntered)
			f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o666)
			if err == nil {
				err = f.Close()
			}
			return err
		})
	}()

	select {
	case <-secondEntered:
		t.Fatal("creation without umask= entered while the process umask was changed")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("mode=%#o want 0644", got)
	}
}
