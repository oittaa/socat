package xio

import (
	"fmt"
	"os"
	"sync"

	"github.com/oittaa/socat/internal/parse"
)

// RejectUnsupportedOpenpty rejects the openpty selector. PTY allocation is
// /dev/ptmx via pty or ptmx; a distinct openpty mechanism is not implemented.
func RejectUnsupportedOpenpty(s parse.Spec) error {
	for _, name := range []string{"openpty"} {
		if o, ok := s.OptionNamed(name); ok {
			return fmt.Errorf("%s: %s is not supported", s.Type, o.OriginalSpelling())
		}
	}
	return nil
}

// CreatePtySlaveLink creates link= / symbolic-link as a symlink to the PTY
// slave. The returned cleanup unlinks only the symlink this call created.
func CreatePtySlaveLink(s parse.Spec, slaveName string) (func(), error) {
	o, ok := s.OptionNamed("link")
	if !ok {
		return func() {}, nil
	}
	path := o.Value
	if !o.Has || path == "" {
		return func() {}, fmt.Errorf("link: path required")
	}
	if err := Unlink(path); err != nil && !os.IsNotExist(err) {
		return func() {}, fmt.Errorf("link: %w", err)
	}
	if err := os.Symlink(slaveName, path); err != nil {
		return func() {}, fmt.Errorf("link: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = Unlink(path)
		return func() {}, fmt.Errorf("link: %w", err)
	}
	if !snapshotRegisteredIdentity(info) {
		_ = Unlink(path)
		return func() {}, fmt.Errorf("link: cannot identify %s", path)
	}
	unreg := RegisterUnlinkPathIdentity(path, info)
	var once sync.Once
	return func() {
		once.Do(func() {
			unreg()
			UnlinkIfSameFile(path, info)
		})
	}, nil
}
