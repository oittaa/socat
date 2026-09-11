package xio

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
)

// ConfiguredFileMode returns the final perm=/mode= operand for open(2).
func ConfiguredFileMode(config addrconfig.File, def os.FileMode) os.FileMode {
	mode := def
	for _, action := range config.Actions {
		if action.Kind == addrconfig.FileActionPerm {
			mode = UnixModeToFileMode(action.Mode)
		}
	}
	return mode
}

// ApplyConfiguredNamedAttrs applies typed perm/user/group actions to a
// filesystem name. User and group lookup intentionally remains at this
// resource-application point.
func ApplyConfiguredNamedAttrs(path string, f *os.File, config addrconfig.File) error {
	for _, action := range config.Actions {
		switch action.Kind {
		case addrconfig.FileActionPerm:
			if err := applyConfiguredNamedPerm(path, f, action.Mode); err != nil {
				return err
			}
		case addrconfig.FileActionUser:
			if err := applyConfiguredNamedUser(path, f, action.Text); err != nil {
				return err
			}
		case addrconfig.FileActionGroup:
			if err := applyConfiguredNamedGroup(path, f, action.Text); err != nil {
				return err
			}
		}
	}
	return nil
}

// ApplyConfiguredOwner applies typed user/group actions to a named file. The
// CREATE owner remains descriptor-owned, matching the former raw path.
func ApplyConfiguredOwner(path, addressType string, f *os.File, config addrconfig.File) error {
	if addressType == "CREATE" || addressType == "CREAT" {
		return nil
	}
	for _, action := range config.Actions {
		switch action.Kind {
		case addrconfig.FileActionUser:
			if err := applyConfiguredNamedUser(path, f, action.Text); err != nil {
				return err
			}
		case addrconfig.FileActionGroup:
			if err := applyConfiguredNamedGroup(path, f, action.Text); err != nil {
				return err
			}
		}
	}
	return nil
}

// ApplyConfiguredNamedPreopen applies typed after-name, before-open actions.
// Name lookup remains deliberately deferred to preserve user/group timing.
func ApplyConfiguredNamedPreopen(path string, config addrconfig.File) error {
	for _, action := range config.Actions {
		switch action.Kind {
		case addrconfig.FileActionPermEarly:
			noteLifecycleSyscall("chmod")
			if err := os.Chmod(path, UnixModeToFileMode(action.Mode)); err != nil {
				return fmt.Errorf("chmod %s: %w", path, err)
			}
		case addrconfig.FileActionUserEarly:
			uid, hasUID, err := resolveUID(action.Text)
			if err != nil {
				return err
			}
			if hasUID {
				if err := os.Chown(path, uid, -1); err != nil {
					return fmt.Errorf("chown %s: %w", path, err)
				}
			}
		case addrconfig.FileActionGroupEarly:
			gid, hasGID, err := resolveGID(action.Text)
			if err != nil {
				return err
			}
			if hasGID {
				if err := os.Chown(path, -1, gid); err != nil {
					return fmt.Errorf("chown %s: %w", path, err)
				}
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
	noteLifecycleSyscall("chmod")
	if path != "" {
		return os.Chmod(path, UnixModeToFileMode(mode))
	}
	if f != nil {
		return f.Chmod(UnixModeToFileMode(mode))
	}
	return nil
}

func applyConfiguredNamedUser(path string, f *os.File, value string) error {
	uid, hasUID, err := resolveUID(value)
	if err != nil {
		return err
	}
	if !hasUID {
		return nil
	}
	noteLifecycleSyscall("chown")
	return namedChown(path, f, uid, -1)
}

func applyConfiguredNamedGroup(path string, f *os.File, value string) error {
	gid, hasGID, err := resolveGID(value)
	if err != nil {
		return err
	}
	if !hasGID {
		return nil
	}
	noteLifecycleSyscall("chown")
	return namedChown(path, f, -1, gid)
}

// WithConfiguredUmask applies an already-validated umask around resource
// creation. It shares the process-wide lock with the raw compatibility path.
func WithConfiguredUmask(config addrconfig.File, fn func() error) error {
	return withConfiguredUmask(config.Umask, fn)
}
