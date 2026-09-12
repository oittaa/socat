package fileopen

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

type openFlag struct {
	id        addrconfig.OpenFlag
	bit       int
	supported bool
}

var openFlagByID = make(map[addrconfig.OpenFlag]openFlag, len(openFlagTable))

func init() {
	for _, f := range openFlagTable {
		openFlagByID[f.id] = f
	}
}

func ConfiguredOpenFlags(config addrconfig.File, mode xio.Mode) (int, error) {
	var flags int
	switch config.Access {
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
	if config.Create.Value {
		flags |= os.O_CREATE
	}
	if config.Exclusive {
		flags |= os.O_EXCL
	}
	if config.Append {
		flags |= os.O_APPEND
	}
	if config.Truncate {
		flags |= os.O_TRUNC
	}
	if config.Nonblock {
		flags |= oNonblock
	}
	return configuredOpenFlags(config, flags)
}

func configuredOpenFlags(config addrconfig.File, flags int) (int, error) {
	for _, action := range config.Actions {
		id := action.Flag
		switch action.Kind {
		case addrconfig.FileActionOpenFlag:
		case addrconfig.FileActionAsync:
			id = addrconfig.OpenFlagAsync
		default:
			continue
		}
		flag, ok := openFlagByID[id]
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

func rejectUnnamedPIPEOpenFlags(config addrconfig.File) error {
	return rejectEnabledOpenFlags(config, "not supported on unnamed PIPE")
}

func rejectGOPENSocketOpenFlags(config addrconfig.File) error {
	return rejectEnabledOpenFlags(config, "not supported when GOPEN resolves to a socket")
}

func rejectEnabledOpenFlags(config addrconfig.File, reason string) error {
	for _, action := range config.Actions {
		if action.Kind != addrconfig.FileActionOpenFlag || !action.Enabled {
			continue
		}
		flag, ok := openFlagByID[action.Flag]
		if !ok {
			continue
		}
		if !flag.supported {
			return fmt.Errorf("%s: not supported on this platform", action.Name)
		}
		return fmt.Errorf("%s: %s", action.Name, reason)
	}
	return nil
}
