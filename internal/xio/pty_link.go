package xio

import (
	"fmt"
	"os"
	"sync"

	"github.com/oittaa/socat/internal/addrconfig"
)

// CreateConfiguredPtySlaveLink creates a PTY link from prepared terminal
// configuration. The link target was decoded before resources were acquired;
// its filesystem work intentionally remains here.
func CreateConfiguredPtySlaveLink(config addrconfig.Address, slaveName string) (func(), error) {
	if !config.Terminal.Link.Set {
		return func() {}, nil
	}
	path := config.Terminal.Link.Value
	if path == "" {
		return func() {}, fmt.Errorf("link: path required")
	}
	if err := Unlink(path); err != nil && !os.IsNotExist(err) {
		return func() {}, fmt.Errorf("link: %w", err)
	}
	if err := os.Symlink(slaveName, path); err != nil {
		return func() {}, fmt.Errorf("link: %w", err)
	}
	if config.File.UnlinkClose.Set && !config.File.UnlinkClose.Value {
		return func() {}, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = Unlink(path)
		return func() {}, fmt.Errorf("link: %w", err)
	}
	if !SnapshotFileIdentity(info) {
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
