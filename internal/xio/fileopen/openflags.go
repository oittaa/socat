package fileopen

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

// openFlag is one open(2) bit (o-direct, o-sync, …) or async (O_ASYNC),
// OR'd into the open flags.
type openFlag struct {
	name      string
	bit       int
	supported bool
}

var openFlagByName = make(map[string]openFlag, len(openFlagTable))

func init() {
	for _, f := range openFlagTable {
		openFlagByName[f.name] = f
	}
}

// ConfiguredOpenFlags derives open(2) bits from typed configuration. It is
// used by prepared file address openers.
func ConfiguredOpenFlags(config addrconfig.File, mode xio.Mode) (int, error) {
	var flags int
	switch config.Open.Access {
	case addrconfig.FileAccessRead:
		flags = os.O_RDONLY
	case addrconfig.FileAccessWrite:
		flags = os.O_WRONLY
	case addrconfig.FileAccessReadWrite:
		flags = os.O_RDWR
	default:
		switch mode {
		case xio.ModeRead:
			flags = os.O_RDONLY
		case xio.ModeWrite:
			flags = os.O_WRONLY
		default:
			flags = os.O_RDWR
		}
	}
	if config.Open.Create {
		flags |= os.O_CREATE
	}
	if config.Open.Exclusive {
		flags |= os.O_EXCL
	}
	if config.Open.Append {
		flags |= os.O_APPEND
	}
	if config.Open.Truncate {
		flags |= os.O_TRUNC
	}
	if config.Open.Nonblock {
		flags |= oNonblock
	}
	return configuredOpenFlags(config, flags)
}

func configuredOpenFlags(config addrconfig.File, flags int) (int, error) {
	for _, action := range config.Open.Flags {
		flag, ok := openFlagByName[action.Name]
		if !ok {
			continue
		}
		if action.Enabled && !flag.supported {
			return 0, fmt.Errorf("%s: not supported on this platform", action.Name)
		}
		if action.Enabled {
			flags |= flag.bit
		} else {
			flags &^= flag.bit
		}
	}
	return flags, nil
}

// rejectUnnamedPIPEOpenFlags rejects enabled o-direct / o-sync / … on
// unnamed PIPE: pipe(2) has no open(2) phase, so those flags would be
// dropped. async is applied later with F_SETFL.
func rejectUnnamedPIPEOpenFlags(config addrconfig.File) error {
	for _, action := range config.Open.Flags {
		if action.Name == "async" || !action.Enabled {
			continue
		}
		flag, ok := openFlagByName[action.Name]
		if !ok {
			continue
		}
		if !flag.supported {
			return fmt.Errorf("%s: not supported on this platform", action.Name)
		}
		return fmt.Errorf("%s: not supported on unnamed PIPE", action.Name)
	}
	return nil
}

// GOPEN delegates an existing socket path to the UNIX address, which has
// no open(2) phase. Reject enabled o-direct / o-sync / … instead of
// silently dropping them. async remains meaningful on the connected socket.
func rejectGOPENSocketOpenFlags(config addrconfig.File) error {
	for _, action := range config.Open.Flags {
		if action.Name == "async" || !action.Enabled {
			continue
		}
		flag, ok := openFlagByName[action.Name]
		if !ok {
			continue
		}
		if !flag.supported {
			return fmt.Errorf("%s: not supported on this platform", action.Name)
		}
		return fmt.Errorf("%s: not supported when GOPEN resolves to a socket", action.Name)
	}
	return nil
}
