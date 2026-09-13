package xio

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
)

func ConfiguredFileMode(config addrconfig.File, def os.FileMode) os.FileMode {
	mode := def
	for _, action := range config.Actions {
		if action.Kind == addrconfig.FileActionPerm {
			mode = UnixModeToFileMode(action.Mode)
		}
	}
	return mode
}

func ApplyConfiguredNamedAttrs(path string, f *os.File, config addrconfig.File) error {
	return applyConfiguredNamed(path, f, config, false)
}

func ApplyConfiguredOwner(path string, kind addrconfig.AddressKind, f *os.File, config addrconfig.File) error {
	if kind == addrconfig.AddressKindCREATE {
		return nil
	}
	return applyConfiguredNamed(path, f, config, true)
}

func applyConfiguredNamed(path string, f *os.File, config addrconfig.File, ownerOnly bool) error {
	for _, action := range config.Actions {
		switch action.Kind {
		case addrconfig.FileActionPerm:
			if !ownerOnly {
				if err := applyConfiguredNamedPerm(path, f, action.Mode); err != nil {
					return err
				}
			}
		case addrconfig.FileActionUser:
			if err := applyConfiguredNamedOwner(path, f, action.Owner, true); err != nil {
				return err
			}
		case addrconfig.FileActionGroup:
			if err := applyConfiguredNamedOwner(path, f, action.Owner, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func ApplyConfiguredNamedPreopen(path string, config addrconfig.File) error {
	for _, action := range config.Actions {
		switch action.Kind {
		case addrconfig.FileActionPermEarly:
			if err := os.Chmod(path, UnixModeToFileMode(action.Mode)); err != nil {
				return fmt.Errorf("chmod %s: %w", path, err)
			}
		case addrconfig.FileActionUserEarly:
			if err := applyNamedPathOwner(path, action.Owner, true); err != nil {
				return err
			}
		case addrconfig.FileActionGroupEarly:
			if err := applyNamedPathOwner(path, action.Owner, false); err != nil {
				return err
			}
		case addrconfig.FileActionUnlink:
			if action.Enabled {
				if err := Unlink(path); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("unlink %s: %w", path, err)
				}
			}
		}
	}
	return nil
}

func applyConfiguredNamedPerm(path string, f *os.File, mode uint32) error {
	if path != "" {
		return os.Chmod(path, UnixModeToFileMode(mode))
	}
	if f != nil {
		return f.Chmod(UnixModeToFileMode(mode))
	}
	return nil
}

func applyConfiguredNamedOwner(path string, f *os.File, owner addrconfig.OwnerRef, user bool) error {
	id, has, err := lookupOwnerID(owner, user)
	if err != nil || !has {
		return err
	}
	if user {
		return namedChown(path, f, id, -1)
	}
	return namedChown(path, f, -1, id)
}

func applyNamedPathOwner(path string, owner addrconfig.OwnerRef, user bool) error {
	return applyConfiguredNamedOwner(path, nil, owner, user)
}

func lookupOwnerID(owner addrconfig.OwnerRef, user bool) (int, bool, error) {
	if user {
		return resolveUID(owner)
	}
	return resolveGID(owner)
}

func WithConfiguredUmask(config addrconfig.File, fn func() error) error {
	return withConfiguredUmask(config.Umask, fn)
}
